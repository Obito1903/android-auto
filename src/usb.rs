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
                    tracing::debug!(
                        "About to open accessory {:?} (negotiated speed: {:?})",
                        info,
                        info.speed()
                    );
                    if matches!(info.speed(), Some(nusb::Speed::Super | nusb::Speed::SuperPlus)) {
                        tracing::warn!(
                            "Accessory enumerated at USB 3.x SuperSpeed; AOA/Android Auto \
                             generally requires USB 2.0 High Speed. If the handshake stalls, \
                             connect the phone via a USB 2.0 port/cable/hub."
                        );
                    }
                    return info.open().await;
                }
            }
        }
        tracing::debug!("No AOA accessory found among USB devices");
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

/// True if the device descriptor identifies a phone that is already in
/// Android Open Accessory mode (the Google AOA vendor id with one of the two
/// accessory product ids).
pub fn is_in_accessory_mode(info: &nusb::DeviceInfo) -> bool {
    info.vendor_id() == 0x18D1 && matches!(info.product_id(), 0x2D00 | 0x2D01)
}

/// Reset any USB device currently sitting in AOA accessory mode.
///
/// When the head unit process restarts (e.g. after a UI crash) without the
/// phone being physically unplugged, the USB accessory link stays up and the
/// phone keeps its previous Android Auto session alive. The fresh process then
/// inherits a half-dead session: the phone keeps emitting stale encrypted
/// frames that the new TLS connection cannot decrypt, so the handshake never
/// recovers and the only manual cure is to unplug and replug the cable.
///
/// Issuing a USB bus reset re-enumerates the device, which the phone detects as
/// a re-attach and uses to tear down and restart Android Auto cleanly — the
/// programmatic equivalent of that replug. A freshly connected phone is not yet
/// in accessory mode, so this only fires for an inherited/stale session and
/// adds no penalty to the normal first-connect path.
///
/// This is intentionally opt-in (`reset_stale_accessory`): on some stricter
/// xHCI controllers (notably the Tegra `70090000.xusb` on the Nintendo Switch)
/// a reset leaves the AOA bulk pipe / data-toggle state inconsistent and breaks
/// the handshake, so those deployments disable it.
///
/// Returns `true` if at least one accessory was reset (the caller should then
/// give the bus a moment to re-enumerate before scanning again).
pub async fn reset_stale_accessories() -> bool {
    let devs = match nusb::list_devices().await {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!("Could not list USB devices to reset stale accessories: {e}");
            return false;
        }
    };
    let mut any = false;
    for di in devs {
        if !is_in_accessory_mode(&di) {
            continue;
        }
        tracing::warn!(
            "USB device already in AOA accessory mode at startup ({:?}); resetting it to \
             clear any stale Android Auto session inherited from a previous run",
            di
        );
        match di.open().await {
            Ok(dev) => match dev.reset().await {
                Ok(()) => {
                    tracing::info!(
                        "Issued USB reset on stale accessory; the phone should restart \
                         Android Auto cleanly"
                    );
                    any = true;
                }
                Err(e) => tracing::warn!("USB reset on stale accessory failed: {e:?}"),
            },
            Err(e) => tracing::warn!("Could not open stale accessory to reset it: {e:?}"),
        }
    }
    any
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
    ep_in: UsbBulkReader,
    ep_out: UsbBulkWriter,
}

impl AndroidAutoUsb {
    /// construct a new interface to the android usb device
    pub fn new(interface: nusb::Interface) -> Option<Self> {
        if let Ok(r) = interface.endpoint::<nusb::transfer::Bulk, nusb::transfer::In>(0x81) {
            if let Ok(w) = interface.endpoint::<nusb::transfer::Bulk, nusb::transfer::Out>(0x1) {
                return Some(Self {
                    ep_in: UsbBulkReader::new(r),
                    ep_out: UsbBulkWriter::new(w),
                });
            }
        }
        None
    }

    /// split the struct
    pub fn into_split(self) -> (UsbBulkReader, UsbBulkWriter) {
        (self.ep_in, self.ep_out)
    }
}

/// An `AsyncRead` adapter that receives every bulk IN transfer into a **fresh,
/// owned** `nusb::transfer::Buffer` and never recycles buffers across
/// transfers.
///
/// This deliberately bypasses nusb's buffered [`nusb::io::EndpointRead`], which
/// reuses the same DMA buffers for successive transfers (see its `resubmit`).
/// On stricter xHCI controllers (notably the Tegra `70090000.xusb` on the
/// Switch) a recycled IN buffer can surface stale bytes from a previous
/// transfer because of weak DMA ordering/coherency — the exact read-side twin
/// of the write corruption handled by [`UsbBulkWriter`]. Small reads (the
/// 8-byte version response) survive, but the large multi-KiB TLS certificate
/// frame comes back corrupted and rustls rejects it with
/// `InvalidCertificate(BadEncoding)`. Submitting a fresh per-transfer buffer
/// gives the kernel/DMA a pristine destination every time and eliminates the
/// aliasing.
///
/// To keep the bulk pipe saturated on the high-bitrate video stream, several
/// transfers are kept in flight at once (a pipeline of depth
/// [`Self::NUM_TRANSFERS`]). Crucially, each completed buffer is dropped and a
/// brand-new [`nusb::transfer::Buffer`] is submitted in its place — a buffer is
/// never recycled back into a subsequent transfer — so the anti-aliasing
/// guarantee holds while the controller always has a destination ready.
pub struct UsbBulkReader {
    /// The raw bulk IN endpoint.
    ep: nusb::Endpoint<nusb::transfer::Bulk, nusb::transfer::In>,
    /// A completed transfer currently being drained, with our read cursor.
    current: Option<(nusb::transfer::Buffer, usize)>,
    /// `requested_len` for each submitted IN transfer (a multiple of the
    /// endpoint max packet size, as required by `Endpoint::submit`).
    req_len: usize,
    /// Whether the initial batch of transfers has been queued.
    primed: bool,
}

impl UsbBulkReader {
    /// Number of bulk IN transfers kept in flight to keep the pipe saturated.
    const NUM_TRANSFERS: usize = 4;

    /// Wrap a raw bulk IN endpoint.
    pub fn new(ep: nusb::Endpoint<nusb::transfer::Bulk, nusb::transfer::In>) -> Self {
        // IN transfers must request a nonzero multiple of the max packet size.
        // Request a generous span so a whole Android Auto frame arrives in one
        // transfer (it ends at the first short packet).
        let mps = ep.max_packet_size().max(1);
        let req_len = mps * 32;
        Self {
            ep,
            current: None,
            req_len,
            primed: false,
        }
    }
}

impl tokio::io::AsyncRead for UsbBulkReader {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let me = self.get_mut();

        // Prime the pipeline with a batch of fresh transfers on first poll.
        if !me.primed {
            for _ in 0..Self::NUM_TRANSFERS {
                me.ep.submit(nusb::transfer::Buffer::new(me.req_len));
            }
            me.primed = true;
        }

        loop {
            // Drain any bytes still buffered from the last completed transfer.
            if let Some((completed, cursor)) = &mut me.current {
                let data: &[u8] = completed;
                if *cursor < data.len() {
                    let n = (data.len() - *cursor).min(buf.remaining());
                    buf.put_slice(&data[*cursor..*cursor + n]);
                    *cursor += n;
                    return std::task::Poll::Ready(Ok(()));
                }
                me.current = None;
            }

            match me.ep.poll_next_complete(cx) {
                std::task::Poll::Ready(completion) => {
                    // Replace the just-completed transfer with a brand-new
                    // buffer (never recycle the completed one) so the pipeline
                    // stays full and no buffer is reused across transfers.
                    me.ep.submit(nusb::transfer::Buffer::new(me.req_len));
                    if let Err(e) = completion.status {
                        return std::task::Poll::Ready(Err(std::io::Error::other(format!(
                            "usb bulk in transfer failed: {e:?}"
                        ))));
                    }
                    me.current = Some((completion.buffer, 0));
                    // Loop back to drain the freshly received bytes.
                }
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
    }
}

/// An `AsyncWrite` adapter that sends every Android Auto frame as its own bulk
/// transfer using an **owned** `nusb::transfer::Buffer`.
///
/// This deliberately bypasses nusb's buffered [`nusb::io::EndpointWrite`]. On
/// stricter xHCI controllers (notably the Tegra `70090000.xusb` on the Switch)
/// the buffered writer hands the kernel a DMA buffer whose contents lag the
/// requested length by one transfer: the first OUT transfer goes out as all
/// zeros and each subsequent transfer carries the *previous* frame's bytes.
/// The phone then receives a corrupt version request, rejects the session with
/// a 2-byte `0xffff` control frame, and the handshake never completes. (The
/// same code works on x86 hosts thanks to coherent DMA and stronger memory
/// ordering, which is why this only reproduces on the Switch.)
///
/// By submitting an owned, per-frame buffer the kernel always sees exactly the
/// bytes we intended, eliminating the aliasing/lag.
pub struct UsbBulkWriter {
    /// The raw bulk OUT endpoint.
    ep: nusb::Endpoint<nusb::transfer::Bulk, nusb::transfer::Out>,
    /// Whether a transfer submitted by `poll_write` is still in flight.
    pending: bool,
}

impl UsbBulkWriter {
    /// Wrap a raw bulk OUT endpoint.
    pub fn new(ep: nusb::Endpoint<nusb::transfer::Bulk, nusb::transfer::Out>) -> Self {
        Self { ep, pending: false }
    }

    /// Drive the in-flight transfer (if any) to completion, surfacing any
    /// transfer error. `poll_next_complete` panics if nothing is pending, so it
    /// is only polled while `self.pending` is set.
    fn poll_drain(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.pending {
            match self.ep.poll_next_complete(cx) {
                std::task::Poll::Ready(completion) => {
                    self.pending = false;
                    if let Err(e) = completion.status {
                        return std::task::Poll::Ready(Err(std::io::Error::other(format!(
                            "usb bulk out transfer failed: {e:?}"
                        ))));
                    }
                }
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
        std::task::Poll::Ready(Ok(()))
    }
}

impl tokio::io::AsyncWrite for UsbBulkWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let me = self.get_mut();
        // Finish the previous frame's transfer before queuing the next so that
        // frames are sent in order and back-pressure is applied.
        if let std::task::Poll::Pending = me.poll_drain(cx)? {
            return std::task::Poll::Pending;
        }
        if buf.is_empty() {
            return std::task::Poll::Ready(Ok(0));
        }
        // Submit an owned copy: the kernel/DMA sees exactly these bytes.
        me.ep
            .submit(nusb::transfer::Buffer::from(buf.to_vec()));
        me.pending = true;
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.get_mut().poll_drain(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.get_mut().poll_drain(cx)
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
        tracing::trace!("{} raw {} bytes: {:02x?}", label, bytes.len(), &bytes[..cap]);
    } else {
        tracing::trace!("{} raw {} bytes: {:02x?}", label, bytes.len(), &bytes[..cap]);
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
