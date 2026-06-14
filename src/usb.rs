#[repr(u16)]
enum AoaStringIndex {
    Manufacturer = 0,
    Model = 1,
    Description = 2,
    Version = 3,
    Uri = 4,
    SerialNumber = 5,
}

async fn send_aoa_string(
    device: &nusb::Device,
    index: u16,
    value: &str,
) -> Result<(), nusb::transfer::TransferError> {
    device
        .control_out(
            nusb::transfer::ControlOut {
                control_type: nusb::transfer::ControlType::Vendor,
                recipient: nusb::transfer::Recipient::Device,
                request: 52,
                value: 0,
                data: value.as_bytes(),
                index,
            },
            std::time::Duration::from_millis(1000),
        )
        .await?;
    Ok(())
}

pub async fn identify_accessory(
    device: &nusb::Device,
) -> Result<(), nusb::transfer::TransferError> {
    send_aoa_string(device, AoaStringIndex::Manufacturer as u16, "Android").await?;
    send_aoa_string(device, AoaStringIndex::Model as u16, "Android Auto").await?;
    send_aoa_string(device, AoaStringIndex::Description as u16, "Android Auto").await?;
    send_aoa_string(device, AoaStringIndex::Version as u16, "2.0.1").await?;
    send_aoa_string(device, AoaStringIndex::Uri as u16, "").await?;
    send_aoa_string(device, AoaStringIndex::SerialNumber as u16, "HU-AAAAAA").await?;
    Ok(())
}

pub async fn accessory_start(
    device: &nusb::Device,
) -> Result<(), nusb::transfer::TransferError> {
    device
        .control_out(
            nusb::transfer::ControlOut {
                control_type: nusb::transfer::ControlType::Vendor,
                recipient: nusb::transfer::Recipient::Device,
                request: 53,
                value: 0,
                data: &[],
                index: 0,
            },
            std::time::Duration::from_millis(1000),
        )
        .await?;
    Ok(())
}

pub async fn wait_for_accessory() -> Result<nusb::Device, nusb::Error> {
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        if let Ok(devices) = nusb::list_devices().await {
            for info in devices {
                if info.vendor_id() == 0x18d1
                    && (info.product_id() == 0x2D00 || info.product_id() == 0x2D01)
                {
                    // Android Open Accessory is a USB 2.0 protocol. Many phones
                    // misbehave when the accessory link enumerates at SuperSpeed
                    // (USB 3.x), so surface the negotiated speed to make that
                    // failure mode diagnosable from the logs.
                    log::info!(
                        "About to open accessory {:?} (negotiated speed: {:?})",
                        info,
                        info.speed()
                    );
                    if matches!(info.speed(), Some(nusb::Speed::Super | nusb::Speed::SuperPlus)) {
                        log::warn!(
                            "Accessory enumerated at USB 3.x SuperSpeed; AOA/Android Auto \
                             generally requires USB 2.0 High Speed. If the handshake stalls, \
                             connect the phone via a USB 2.0 port/cable/hub."
                        );
                    }
                    return info.open().await;
                }
            }
        }
        log::info!("Didnt find accessory");
    }
}

/// Determines if the usb device is an android device
pub fn is_android_device(info: &nusb::DeviceInfo) -> bool {
    // Already in accessory mode - best case
    if info.vendor_id() == 0x18D1 && matches!(info.product_id(), 0x2D00 | 0x2D01) {
        return true;
    }

    // Has an ADB interface (class 0xFF, subclass 0x42, protocol 0x01)
    if info
        .interfaces()
        .any(|i| i.class() == 0xFF && i.subclass() == 0x42 && i.protocol() == 0x01)
    {
        return true;
    }

    // MTP/PTP mode (what your Pixel 7 showed)
    if info
        .interfaces()
        .any(|i| i.class() == 0x06 && i.subclass() == 0x01)
    {
        return true;
    }

    false
}

/// if possible, get the aoa protocol number from the device
pub async fn get_aoa_protocol(dev: &nusb::Device) -> Option<u16> {
    let result = dev
        .control_in(
            nusb::transfer::ControlIn {
                control_type: nusb::transfer::ControlType::Vendor,
                recipient: nusb::transfer::Recipient::Device,
                request: 51,
                value: 0,
                index: 0,
                length: 2,
            },
            std::time::Duration::from_millis(1000),
        )
        .await;
    if let Ok(r) = result {
        let version = u16::from_le_bytes([r[0], r[1]]);
        if version >= 1 { Some(version) } else { None }
    } else {
        None
    }
}

pub async fn claim_aoa_interface(device: &nusb::Device) -> nusb::Interface {
    // AOA uses interface 0, with one bulk-in and one bulk-out endpoint
    device.claim_interface(0).await.unwrap()
}

pub struct AndroidAutoUsb {
    ep_in: nusb::io::EndpointRead<nusb::transfer::Bulk>,
    ep_out: nusb::io::EndpointWrite<nusb::transfer::Bulk>,
}

impl AndroidAutoUsb {
    /// construct a new interface to the android usb device
    pub fn new(interface: nusb::Interface) -> Option<Self> {
        if let Ok(w) = interface.endpoint::<nusb::transfer::Bulk, nusb::transfer::In>(0x81) {
            let a = w.reader(4096);
            if let Ok(w) = interface.endpoint::<nusb::transfer::Bulk, nusb::transfer::Out>(0x1) {
                let b = w.writer(4096);
                return Some(Self {
                    ep_in: a,
                    ep_out: b,
                });
            }
        }
        None
    }

    /// split the struct
    pub fn into_split(
        self,
    ) -> (
        nusb::io::EndpointRead<nusb::transfer::Bulk>,
        nusb::io::EndpointWrite<nusb::transfer::Bulk>,
    ) {
        (self.ep_in, self.ep_out)
    }
}

/// An `AsyncRead`/`AsyncWrite` adapter that logs the raw bytes crossing the
/// USB bulk endpoints. This sits *below* the Android Auto framing layer so the
/// exact on-wire transfer boundaries and contents are visible. Small transfers
/// (the version/SSL handshake) are logged at info; larger transfers (video,
/// audio) are logged at debug to avoid flooding normal operation.
pub struct LoggingIo<T> {
    /// The wrapped endpoint reader/writer.
    inner: T,
    /// A short label identifying the direction in the logs.
    label: &'static str,
}

impl<T> LoggingIo<T> {
    /// Wrap an endpoint with raw-byte logging under the given label.
    pub fn new(inner: T, label: &'static str) -> Self {
        Self { inner, label }
    }
}

/// Log a raw USB chunk, capping the displayed bytes and using info for small
/// (handshake-sized) transfers, debug for larger ones.
fn log_raw(label: &str, bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    let cap = bytes.len().min(64);
    if bytes.len() <= 64 {
        log::info!("{} raw {} bytes: {:02x?}", label, bytes.len(), &bytes[..cap]);
    } else {
        log::debug!("{} raw {} bytes: {:02x?}", label, bytes.len(), &bytes[..cap]);
    }
}

impl<T: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for LoggingIo<T> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let me = self.get_mut();
        let before = buf.filled().len();
        let r = std::pin::Pin::new(&mut me.inner).poll_read(cx, buf);
        if let std::task::Poll::Ready(Ok(())) = &r {
            let new = &buf.filled()[before..];
            log_raw(me.label, new);
        }
        r
    }
}

impl<T: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for LoggingIo<T> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let me = self.get_mut();
        let r = std::pin::Pin::new(&mut me.inner).poll_write(cx, buf);
        if let std::task::Poll::Ready(Ok(n)) = &r {
            log_raw(me.label, &buf[..*n]);
        }
        r
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let me = self.get_mut();
        std::pin::Pin::new(&mut me.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let me = self.get_mut();
        std::pin::Pin::new(&mut me.inner).poll_shutdown(cx)
    }
}
