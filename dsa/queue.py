"""
queue.py - Custom Queue for Outgoing Message Management
Uses a doubly linked list internally for O(1) enqueue and dequeue.
Time Complexity: Enqueue O(1), Dequeue O(1), Peek O(1)
Space Complexity: O(n)
"""


class QueueNode:
    """Internal node for the message queue."""

    def __init__(self, data):
        """
        Initialize queue node.
        Args:
            data: Any message payload
        """
        self.data = data
        self.next = None


class MessageQueue:
    """
    Custom FIFO queue for outgoing stego-image messages.
    Messages are enqueued by the sender and dequeued by the network layer.
    """

    def __init__(self, max_size: int = 100):
        """
        Initialize the message queue.
        Args:
            max_size (int): Maximum number of pending messages (DoS protection)
        """
        self.front = None
        self.rear = None
        self._size = 0
        self.max_size = max_size

    def enqueue(self, data) -> bool:
        """
        Add a message to the rear of the queue. O(1)
        Args:
            data: Message payload to queue
        Returns:
            bool: True if enqueued, False if queue is full (DoS protection)
        """
        if self._size >= self.max_size:
            return False  # Drop message — DoS protection

        node = QueueNode(data)
        if self.rear is None:
            self.front = self.rear = node
        else:
            self.rear.next = node
            self.rear = node
        self._size += 1
        return True

    def dequeue(self):
        """
        Remove and return message from the front. O(1)
        Returns:
            Message payload or None if empty
        """
        if self.front is None:
            return None
        data = self.front.data
        self.front = self.front.next
        if self.front is None:
            self.rear = None
        self._size -= 1
        return data

    def peek(self):
        """
        View the front message without removing it. O(1)
        Returns:
            Message payload or None if empty
        """
        if self.front is None:
            return None
        return self.front.data

    def is_empty(self) -> bool:
        """Check if queue is empty. O(1)"""
        return self._size == 0

    def is_full(self) -> bool:
        """Check if queue has reached capacity. O(1)"""
        return self._size >= self.max_size

    def size(self) -> int:
        """Return current queue size. O(1)"""
        return self._size

    def clear(self):
        """Clear all pending messages. O(1)"""
        self.front = None
        self.rear = None
        self._size = 0

    def to_list(self) -> list:
        """Return all queued items as a list without dequeuing. O(n)"""
        result = []
        current = self.front
        while current:
            result.append(current.data)
            current = current.next
        return result

    def __len__(self):
        return self._size

    def __repr__(self):
        return f"MessageQueue(size={self._size}, max={self.max_size})"


class RateLimiterBucket:
    """
    Token bucket algorithm for DoS rate limiting.
    Limits how many messages a user can send per second.
    Time Complexity: O(1) per check
    """

    def __init__(self, capacity: int = 10, refill_rate: float = 2.0):
        """
        Initialize token bucket.
        Args:
            capacity (int): Max burst size (tokens)
            refill_rate (float): Tokens added per second
        """
        import time
        self.capacity = capacity
        self.tokens = capacity
        self.refill_rate = refill_rate
        self.last_refill = time.time()

    def consume(self, tokens: int = 1) -> bool:
        """
        Attempt to consume tokens. Refills based on elapsed time. O(1)
        Args:
            tokens (int): Number of tokens to consume (1 per message)
        Returns:
            bool: True if allowed, False if rate limited
        """
        import time
        now = time.time()
        elapsed = now - self.last_refill
        refill_amount = elapsed * self.refill_rate
        self.tokens = min(self.capacity, self.tokens + refill_amount)
        self.last_refill = now

        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False

    def available(self) -> float:
        """Return current available tokens. O(1)"""
        return self.tokens