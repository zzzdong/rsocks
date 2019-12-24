pub mod dns;
pub mod socks5;

pub trait WriteBuf {
    fn write_buf(&self, buf: &mut bytes::BytesMut);
}
