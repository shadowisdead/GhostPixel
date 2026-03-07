"""
linked_list.py - Custom Doubly Linked List for Message History
Time Complexity: Append O(1), Search O(n), Delete O(n)
Space Complexity: O(n)
"""


class MessageNode:
    """A single node in the message history chain."""

    def __init__(self, data: dict):
        """
        Initialize a message node.
        Args:
            data (dict): Message payload {id, sender, content, timestamp, tampered}
        """
        self.data = data
        self.prev = None
        self.next = None


class MessageLinkedList:
    """
    Custom doubly linked list to store chat message history.
    Each node represents one decrypted message.
    """

    def __init__(self):
        """Initialize empty linked list."""
        self.head = None
        self.tail = None
        self._size = 0

    def append(self, data: dict) -> MessageNode:
        """
        Append a new message to the end of the list. O(1)
        Args:
            data (dict): Message data dictionary
        Returns:
            MessageNode: The newly created node
        """
        node = MessageNode(data)
        if self.tail is None:
            self.head = self.tail = node
        else:
            node.prev = self.tail
            self.tail.next = node
            self.tail = node
        self._size += 1
        return node

    def prepend(self, data: dict) -> MessageNode:
        """
        Prepend a message to the front of the list. O(1)
        Args:
            data (dict): Message data dictionary
        Returns:
            MessageNode: The newly created node
        """
        node = MessageNode(data)
        if self.head is None:
            self.head = self.tail = node
        else:
            node.next = self.head
            self.head.prev = node
            self.head = node
        self._size += 1
        return node

    def delete(self, message_id: str) -> bool:
        """
        Delete a message node by message ID. O(n)
        Args:
            message_id (str): Unique message identifier
        Returns:
            bool: True if deleted, False if not found
        """
        current = self.head
        while current:
            if current.data.get("id") == message_id:
                if current.prev:
                    current.prev.next = current.next
                else:
                    self.head = current.next
                if current.next:
                    current.next.prev = current.prev
                else:
                    self.tail = current.prev
                self._size -= 1
                return True
            current = current.next
        return False

    def search(self, message_id: str) -> MessageNode | None:
        """
        Search for a message by ID. O(n)
        Args:
            message_id (str): Unique message identifier
        Returns:
            MessageNode or None
        """
        current = self.head
        while current:
            if current.data.get("id") == message_id:
                return current
            current = current.next
        return None

    def to_list(self) -> list:
        """
        Convert linked list to Python list. O(n)
        Returns:
            list: All message data dictionaries in order
        """
        result = []
        current = self.head
        while current:
            result.append(current.data)
            current = current.next
        return result

    def clear(self):
        """Clear all messages from the list. O(1)"""
        self.head = None
        self.tail = None
        self._size = 0

    def size(self) -> int:
        """Return current number of messages. O(1)"""
        return self._size

    def __len__(self):
        return self._size

    def __iter__(self):
        current = self.head
        while current:
            yield current.data
            current = current.next

    def __repr__(self):
        return f"MessageLinkedList(size={self._size})"