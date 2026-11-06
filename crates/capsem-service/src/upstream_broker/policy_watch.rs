//! Policy followers beside the session's upstream brokers.
use super::*;

/// A session policy subscriber outside the upstream brokers. Merged into the
/// session's publisher, it acknowledges an update only once the returned
/// watch holds it, so a policy publish completes after this reader sees it.
pub(crate) fn policy_watch(
    initial: Arc<BrokerPolicy>,
) -> (tokio::sync::watch::Receiver<Arc<BrokerPolicy>>, PolicyPublisher) {
    let (updates_tx, mut updates) = mpsc::channel::<PolicyUpdate>(1);
    let (current, watch) = tokio::sync::watch::channel(initial);
    tokio::spawn(async move {
        while let Some(update) = updates.recv().await {
            current.send_replace(update.policy);
            let _ = update.applied.send(Ok(()));
        }
    });
    (
        watch,
        PolicyPublisher {
            updates: vec![updates_tx],
        },
    )
}
