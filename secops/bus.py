"""Kafka-style event bus. A topic is an append-only log; each consumer group keeps
its own offset. Processing is at-least-once: consume -> process -> commit.
In production this interface would be backed by Apache Kafka (or GCP Pub/Sub)."""
from collections import defaultdict


class EventBus:
    def __init__(self):
        self.topics = defaultdict(list)
        self.offsets = defaultdict(int)  # (topic, group) -> next offset to read

    def publish(self, topic, event):
        self.topics[topic].append(event)
        return len(self.topics[topic]) - 1  # offset of the new event

    def consume(self, topic, group, max_events=100):
        start = self.offsets[(topic, group)]
        return self.topics[topic][start:start + max_events]

    def commit(self, topic, group, n):
        self.offsets[(topic, group)] += n

    def lag(self, topic, group):
        """How many events the group still has to process (a key streaming metric)."""
        return len(self.topics[topic]) - self.offsets[(topic, group)]
