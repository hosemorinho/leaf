use std::sync::atomic::{AtomicUsize, Ordering};
use std::{io, sync::Arc};

use async_trait::async_trait;

use crate::{proxy::*, session::Session};

pub struct Handler {
    pub actors: Vec<AnyOutboundHandler>,
    pub selected: Arc<AtomicUsize>,
}

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        let a = &self.actors[self.selected.load(Ordering::Relaxed)];
        match a.stream() {
            Ok(h) => return h.connect_addr(),
            _ => match a.datagram() {
                Ok(h) => return h.connect_addr(),
                _ => (),
            },
        }
        OutboundConnect::Unknown
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        lhs: Option<&mut AnyStream>,
        stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        let idx = self.selected.load(Ordering::Relaxed);
        let a = &self.actors[idx];
        tracing::warn!(
            "select [{}] idx={}/{} arc_ptr={:p} -> [{}]",
            sess.destination,
            idx,
            self.actors.len(),
            &*self.selected as *const AtomicUsize,
            a.tag(),
        );
        a.stream()?.handle(sess, lhs, stream).await
    }
}
