"""
hash_table.py - Custom Hash Table for Session and User Management
Uses separate chaining for collision resolution.
Time Complexity: Insert/Search/Delete avg O(1), worst O(n)
Space Complexity: O(n)
"""


class HashNode:
    """A key-value pair node used in hash table chaining."""

    def __init__(self, key: str, value):
        """
        Initialize hash node.
        Args:
            key (str): Lookup key (username or session token)
            value: Associated value (user data or session info)
        """
        self.key = key
        self.value = value
        self.next = None


class HashTable:
    """
    Custom hash table with separate chaining for collision handling.
    Used to store active user sessions and registered users.
    """

    def __init__(self, capacity: int = 64):
        """
        Initialize hash table.
        Args:
            capacity (int): Number of buckets (default 64)
        """
        self.capacity = capacity
        self.buckets = [None] * self.capacity
        self._size = 0
        self._load_factor_threshold = 0.75

    def _hash(self, key: str) -> int:
        """
        Polynomial rolling hash function. O(k) where k = len(key)
        Args:
            key (str): String key to hash
        Returns:
            int: Bucket index
        """
        hash_val = 0
        prime = 31
        mod = self.capacity
        power = 1
        for char in key:
            hash_val = (hash_val + ord(char) * power) % mod
            power = (power * prime) % mod
        return hash_val

    def _resize(self):
        """Double capacity and rehash all entries when load factor exceeded. O(n)"""
        old_buckets = self.buckets
        self.capacity *= 2
        self.buckets = [None] * self.capacity
        self._size = 0
        for bucket in old_buckets:
            current = bucket
            while current:
                self.insert(current.key, current.value)
                current = current.next

    def insert(self, key: str, value) -> None:
        """
        Insert or update a key-value pair. Avg O(1)
        Args:
            key (str): Lookup key
            value: Value to store
        """
        if self._size / self.capacity >= self._load_factor_threshold:
            self._resize()

        index = self._hash(key)
        current = self.buckets[index]

        while current:
            if current.key == key:
                current.value = value
                return
            current = current.next

        new_node = HashNode(key, value)
        new_node.next = self.buckets[index]
        self.buckets[index] = new_node
        self._size += 1

    def get(self, key: str):
        """
        Retrieve value by key. Avg O(1)
        Args:
            key (str): Lookup key
        Returns:
            Value or None if not found
        """
        index = self._hash(key)
        current = self.buckets[index]
        while current:
            if current.key == key:
                return current.value
            current = current.next
        return None

    def delete(self, key: str) -> bool:
        """
        Remove a key-value pair. Avg O(1)
        Args:
            key (str): Key to remove
        Returns:
            bool: True if deleted, False if not found
        """
        index = self._hash(key)
        current = self.buckets[index]
        prev = None

        while current:
            if current.key == key:
                if prev:
                    prev.next = current.next
                else:
                    self.buckets[index] = current.next
                self._size -= 1
                return True
            prev = current
            current = current.next
        return False

    def contains(self, key: str) -> bool:
        """
        Check if a key exists. Avg O(1)
        Args:
            key (str): Key to check
        Returns:
            bool
        """
        return self.get(key) is not None

    def keys(self) -> list:
        """Return all keys in the hash table. O(n)"""
        result = []
        for bucket in self.buckets:
            current = bucket
            while current:
                result.append(current.key)
                current = current.next
        return result

    def values(self) -> list:
        """Return all values in the hash table. O(n)"""
        result = []
        for bucket in self.buckets:
            current = bucket
            while current:
                result.append(current.value)
                current = current.next
        return result

    def items(self) -> list:
        """Return all (key, value) pairs. O(n)"""
        result = []
        for bucket in self.buckets:
            current = bucket
            while current:
                result.append((current.key, current.value))
                current = current.next
        return result

    def size(self) -> int:
        """Return number of stored entries. O(1)"""
        return self._size

    def clear(self):
        """Clear all entries. O(1)"""
        self.buckets = [None] * self.capacity
        self._size = 0

    def __len__(self):
        return self._size

    def __repr__(self):
        return f"HashTable(size={self._size}, capacity={self.capacity})"