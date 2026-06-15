//! SSL code

use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    AndroidAutoControlMessage, AndroidAutoFrame, AndroidAutoFrameReceiver, FrameHeaderReceiver,
    FrameReceiptError, FrameTransmissionError, SendableAndroidAutoMessage,
};

/// A message sent to the ssl thread
pub enum SslThreadData {
    /// The handshake is starting
    HandshakeStart,
    /// Data to send out for handshake process
    HandshakeData(Vec<u8>),
    /// A message to write to the writer
    PlainData(SendableAndroidAutoMessage),
    /// A frame to write to the writer
    Frame(AndroidAutoFrame),
    /// A message to decrypt
    DecryptMe(AndroidAutoFrame),
}

/// The response from the ssl thread
pub enum SslThreadResponse {
    /// A decrypted frame received from the read object
    Data(AndroidAutoFrame),
    /// The handshake is complete
    HandshakeComplete,
    /// The ssl thread is exiting with an error
    ExitError(String),
}

struct SslStreamThread<U: AsyncWrite + Unpin> {
    stream: rustls::client::ClientConnection,
    hs_started: bool,
    hs_completed: bool,
    hs: Option<tokio::sync::mpsc::Receiver<SslThreadData>>,
    dout: tokio::sync::mpsc::UnboundedSender<SslThreadResponse>,
    write: U,
}

impl<U: AsyncWrite + Unpin> SslStreamThread<U> {
    fn new(
        rcv: tokio::sync::mpsc::Receiver<SslThreadData>,
        dout: tokio::sync::mpsc::UnboundedSender<SslThreadResponse>,
        conn: rustls::client::ClientConnection,
        write: U,
    ) -> Self {
        Self {
            stream: conn,
            hs_started: false,
            hs_completed: false,
            hs: Some(rcv),
            dout,
            write,
        }
    }

    /// Write a frame to the wire, discarding it if it requires encryption but
    /// the TLS handshake has not completed yet. rustls has no session keys
    /// before the handshake finishes, so such a frame cannot be encrypted.
    /// Discarding (rather than queuing) avoids sending application data ahead
    /// of the `SslAuthComplete` control message, which would violate the
    /// protocol. Discarded frames (e.g. periodic sensor data) are re-sent later.
    async fn send_or_discard(&mut self, f: AndroidAutoFrame) -> Result<(), String> {
        if f.header.frame.get_encryption() && !self.hs_completed {
            tracing::debug!(
                "Discarding encrypted frame on channel {} before handshake completion",
                f.header.channel_id
            );
            return Ok(());
        }
        self.write_frame_now(f).await
    }

    /// Build and write a single frame to the underlying writer immediately.
    async fn write_frame_now(&mut self, f: AndroidAutoFrame) -> Result<(), String> {
        use tokio::io::AsyncWriteExt;
        // Log outgoing control-channel traffic in the clear (capped) so the
        // version/SSL handshake exchange can be diagnosed byte-for-byte.
        if f.header.channel_id == 0 && !f.header.frame.get_encryption() {
            let cap = f.data.len().min(64);
            tracing::trace!(
                "TX control frame {:?} len={} data={:02x?}",
                f.header,
                f.data.len(),
                &f.data[..cap]
            );
        }
        let d2: Vec<u8> = f
            .build_vec(Some(&mut self.stream))
            .await
            .map_err(|e| format!("{:?}", e))?;
        let a = self.write.write_all(&d2).await.map_err(|e| match e.kind() {
            std::io::ErrorKind::TimedOut => FrameTransmissionError::Timeout,
            std::io::ErrorKind::UnexpectedEof => FrameTransmissionError::Disconnected,
            _ => FrameTransmissionError::Unexpected(e),
        });
        let _ = self.write.flush().await;
        a.map_err(|e| format!("{:?}", e))
    }

    async fn handle_receive(&mut self, m: SslThreadData) -> Result<(), String> {
        match m {
            SslThreadData::DecryptMe(mut data) => {
                if let Err(e) = data.decrypt(&mut self.stream).await {
                    // Before the fresh TLS handshake completes, a phone that
                    // still holds a session from a previous run (e.g. after the
                    // head unit restarted without a USB replug) can emit leftover
                    // encrypted `ApplicationData` frames. rustls has no session
                    // keys yet, so decryption fails with `InappropriateMessage`.
                    // Dropping such stale frames keeps the connection alive so the
                    // real handshake can proceed, instead of tearing everything
                    // down and forcing a reconnect cycle. Once the handshake has
                    // completed a decrypt error is a genuine failure and is fatal.
                    if !self.hs_completed {
                        tracing::warn!(
                            "Dropping undecryptable frame before handshake completion \
                             (likely stale data from a previous session): {:?}",
                            e
                        );
                        return Ok(());
                    }
                    tracing::error!("Error receiving frame: {:?}", e);
                    return Err(format!("frame error {:?}", e));
                }
                let _ = self.dout.send(SslThreadResponse::Data(data));
            }
            SslThreadData::HandshakeStart => {
                if self.hs_started {
                    // A duplicate `VersionResponse` (seen when a phone replays the
                    // tail of a previous session on reconnect) would drive a second
                    // handshake start. rustls has already emitted its ClientHello,
                    // so re-driving it is meaningless; ignore it rather than
                    // panicking and killing the worker.
                    tracing::warn!(
                        "Ignoring duplicate handshake start (handshake already in progress)"
                    );
                } else {
                    let mut buf = Vec::new();
                    self.stream
                        .write_tls(&mut buf)
                        .map_err(|e| format!("write_tls: {e}"))?;
                    {
                        use tokio::io::AsyncWriteExt;
                        let f: AndroidAutoFrame =
                            AndroidAutoControlMessage::SslHandshake(buf).into();
                        let d2: Vec<u8> = f
                            .build_vec(Some(&mut self.stream))
                            .await
                            .map_err(|e| format!("{:?}", e))?;
                        self.write
                            .write_all(&d2)
                            .await
                            .map_err(|e| match e.kind() {
                                std::io::ErrorKind::TimedOut => "write timed out".to_string(),
                                std::io::ErrorKind::UnexpectedEof => {
                                    "write disconnected".to_string()
                                }
                                _ => format!("write error: {e}"),
                            })?;
                        let _ = self.write.flush().await;
                        self.hs_started = true;
                    }
                }
            }
            SslThreadData::HandshakeData(data) => {
                let mut dc = std::io::Cursor::new(data);
                self.stream
                    .read_tls(&mut dc)
                    .map_err(|e| format!("read_tls: {e}"))?;
                let state = self
                    .stream
                    .process_new_packets()
                    .map_err(|e| format!("{:?}", e))?;

                if state.peer_has_closed() {
                    return Err("peer closed connection during handshake".to_string());
                }
                if !self.stream.is_handshaking() && !self.hs_completed {
                    self.hs_completed = true;
                    self.dout
                        .send(SslThreadResponse::HandshakeComplete)
                        .map_err(|e| e.to_string())?;
                }

                if self.stream.wants_write() {
                    use tokio::io::AsyncWriteExt;
                    let mut s = Vec::new();
                    self.stream
                        .write_tls(&mut s)
                        .map_err(|e| format!("write_tls: {e}"))?;
                    {
                        let f: AndroidAutoFrame = AndroidAutoControlMessage::SslHandshake(s).into();
                        let d2: Vec<u8> = f
                            .build_vec(Some(&mut self.stream))
                            .await
                            .map_err(|e| format!("{:?}", e))?;
                        self.write
                            .write_all(&d2)
                            .await
                            .map_err(|e| match e.kind() {
                                std::io::ErrorKind::TimedOut => "Timed out".to_string(),
                                std::io::ErrorKind::UnexpectedEof => "Disconnected".to_string(),
                                _ => format!("write error: {e}"),
                            })?;
                        let _ = self.write.flush().await;
                    }
                }
            }
            SslThreadData::PlainData(f) => {
                if let Some(frame) = f.into_frame().await {
                    self.send_or_discard(frame).await?;
                } else {
                    tracing::warn!("Dropping message: no matching channel handler available yet");
                }
            }
            SslThreadData::Frame(f) => {
                self.send_or_discard(f).await?;
            }
        }
        Ok(())
    }

    async fn run(mut self) -> Result<(), String> {
        let mut hs = self
            .hs
            .take()
            .expect("SslStreamThread::run called without receiver");
        loop {
            match hs.recv().await {
                Some(m) => {
                    if let Err(e) = self.handle_receive(m).await {
                        let _ = self
                            .dout
                            .send(SslThreadResponse::ExitError(e.to_string()));
                        return Err(e);
                    }
                }
                None => {
                    return Ok(());
                }
            }
        }
    }
}

pub struct StreamMux {
    send: tokio::sync::mpsc::Sender<SslThreadData>,
    recv: tokio::sync::mpsc::UnboundedReceiver<SslThreadResponse>,
}

pub struct ReadHalf {
    recv: tokio::sync::mpsc::UnboundedReceiver<SslThreadResponse>,
}

#[derive(Clone)]
pub struct WriteHalf {
    send: tokio::sync::mpsc::Sender<SslThreadData>,
}

impl WriteHalf {
    pub async fn write_message(
        &self,
        m: SendableAndroidAutoMessage,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<SslThreadData>> {
        self.send.send(SslThreadData::PlainData(m)).await
    }

    pub async fn write_frame(
        &self,
        f: AndroidAutoFrame,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<SslThreadData>> {
        self.send.send(SslThreadData::Frame(f)).await
    }

    pub async fn start_handshake(
        &self,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<SslThreadData>> {
        self.send.send(SslThreadData::HandshakeStart).await
    }

    pub async fn do_handshake(
        &self,
        data: Vec<u8>,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<SslThreadData>> {
        self.send.send(SslThreadData::HandshakeData(data)).await
    }
}

impl ReadHalf {
    pub async fn recv(&mut self) -> Option<SslThreadResponse> {
        self.recv.recv().await
    }
}

impl StreamMux {
    pub fn new<T: AsyncRead + Send + Unpin + 'static, U: AsyncWrite + Send + Unpin + 'static>(
        conn: rustls::client::ClientConnection,
        write: U,
        mut read: T,
    ) -> Self {
        let chan = tokio::sync::mpsc::channel(15);
        let chan2 = tokio::sync::mpsc::unbounded_channel();
        let chanw = chan2.0.clone();
        let stream = SslStreamThread::new(chan.1, chan2.0, conn, write);
        tokio::spawn(stream.run());
        let chan_ssl = chan.0.clone();
        tokio::spawn(async move {
            let mut fr = AndroidAutoFrameReceiver::new();
            loop {
                let mut fhr = FrameHeaderReceiver::new();
                match fhr.read(&mut read).await {
                    Ok(Some(fh)) => match fr.read(&fh, &mut read).await {
                        Ok(Some(f)) => {
                            if f.header.frame.get_encryption() {
                                let _ = chan_ssl.send(SslThreadData::DecryptMe(f)).await;
                            } else {
                                // Plaintext control-channel traffic carries the
                                // version/SSL handshake; log it (capped) so a
                                // stalled handshake can be diagnosed.
                                if f.header.channel_id == 0 {
                                    let cap = f.data.len().min(64);
                                    tracing::trace!(
                                        "RX control frame {:?} len={} data={:02x?}",
                                        f.header,
                                        f.data.len(),
                                        &f.data[..cap]
                                    );
                                }
                                let _ = chanw.send(SslThreadResponse::Data(f));
                            }
                        }
                        Ok(None) => {}
                        Err(e) => {
                            // The connection went away (EOF/disconnect) or
                            // produced an unrecoverable read error. Propagate it
                            // so the protocol loop can tear down instead of
                            // spinning forever on a dead stream.
                            tracing::debug!("Reader task stopping: {:?}", e);
                            let _ = chanw
                                .send(SslThreadResponse::ExitError(format!("read error: {:?}", e)));
                            break;
                        }
                    },
                    Ok(None) => {}
                    Err(e) => {
                        tracing::debug!("Reader task stopping: {:?}", e);
                        let _ = chanw
                            .send(SslThreadResponse::ExitError(format!("read error: {:?}", e)));
                        break;
                    }
                }
            }
        });
        Self {
            send: chan.0,
            recv: chan2.1,
        }
    }

    pub fn split(self) -> (ReadHalf, WriteHalf) {
        (ReadHalf { recv: self.recv }, WriteHalf { send: self.send })
    }
}
