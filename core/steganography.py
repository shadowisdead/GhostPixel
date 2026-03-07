"""
steganography.py - LSB Image Steganography Engine
Hides encrypted message bytes inside PNG image pixel data.

Algorithm: Least Significant Bit (LSB) substitution
    - Each pixel has R, G, B channels (0-255 each = 8 bits)
    - We replace the last 2 bits of each channel with message bits
    - 3 channels × 2 bits = 6 bits per pixel
    - Visual change is imperceptible (max value shift ±3)

Capacity: (width × height × 3 × 2) / 8 bytes per image
"""

import os
import struct
from PIL import Image #type: ignore
import io
import base64


class SteganographyEngine:
    """
    LSB Steganography: embeds and extracts hidden data in PNG images.
    Uses 2 least significant bits per RGB channel.
    """

    BITS_PER_CHANNEL = 2          # How many LSBs to use per channel
    CHANNELS = 3                  # R, G, B
    BITS_PER_PIXEL = BITS_PER_CHANNEL * CHANNELS   # 6 bits per pixel
    HEADER_SIZE = 4               # 4 bytes to store message length (uint32)
    MAGIC = b'\xDE\xAD'          # 2-byte magic header to identify stego images

    def __init__(self, carrier_path: str = None):
        """
        Initialize with a carrier image path or use default.
        Args:
            carrier_path (str): Path to carrier PNG image
        """
        self.carrier_path = carrier_path

    def _load_carrier(self) -> Image.Image:
        """Load and validate the carrier image."""
        if self.carrier_path and os.path.exists(self.carrier_path):
            img = Image.open(self.carrier_path).convert("RGB")
        else:
            img = self._generate_noise_carrier(512, 512)
        return img

    @staticmethod
    def _generate_noise_carrier(width: int, height: int) -> Image.Image:
        """
        Generate a random noise PNG as carrier when no image is provided.
        Args:
            width (int): Image width in pixels
            height (int): Image height in pixels
        Returns:
            PIL Image
        """
        import random
        pixels = [
            (random.randint(100, 200), random.randint(100, 200), random.randint(100, 200))
            for _ in range(width * height)
        ]
        img = Image.new("RGB", (width, height))
        img.putdata(pixels)
        return img

    def calculate_capacity(self, image: Image.Image) -> int:
        """
        Calculate max bytes that can be hidden in an image. O(1)
        Args:
            image (PIL Image): Carrier image
        Returns:
            int: Maximum embeddable bytes
        """
        w, h = image.size
        total_bits = w * h * self.BITS_PER_PIXEL
        return (total_bits // 8) - self.HEADER_SIZE - len(self.MAGIC)

    def embed(self, secret_data: bytes, output_path: str = None) -> bytes:
        """
        Embed secret bytes into a carrier image using LSB. O(n)
        Args:
            secret_data (bytes): Encrypted message bytes to hide
            output_path (str): Optional path to save stego image
        Returns:
            bytes: PNG image bytes with embedded data
        Raises:
            ValueError: If message too large for carrier image
        """
        img = self._load_carrier()
        capacity = self.calculate_capacity(img)

        if len(secret_data) > capacity:
            raise ValueError(
                f"Message too large: {len(secret_data)} bytes, "
                f"carrier capacity: {capacity} bytes"
            )

        # Build payload: magic header + 4-byte big-endian length + data
        payload = self.MAGIC + struct.pack(">I", len(secret_data)) + secret_data

        # Convert payload to a flat list of bits (MSB first per byte)
        bits: list[int] = []
        for byte in payload:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)

        pixels = list(img.getdata())
        new_pixels = []
        bit_idx = 0

        # Single clean pass: 2 LSBs per RGB channel
        for pixel in pixels:
            new_channels = []
            for ch_val in pixel[:3]:
                new_ch = ch_val
                for bit_pos in range(1, -1, -1):  # bits 1 then 0
                    if bit_idx < len(bits):
                        new_ch = (new_ch & ~(1 << bit_pos)) | (bits[bit_idx] << bit_pos)
                        bit_idx += 1
                new_channels.append(new_ch)
            new_pixels.append(tuple(new_channels))

        stego_img = Image.new("RGB", img.size)
        stego_img.putdata(new_pixels)

        buf = io.BytesIO()
        stego_img.save(buf, format="PNG")
        image_bytes = buf.getvalue()

        if output_path:
            with open(output_path, "wb") as f:
                f.write(image_bytes)

        return image_bytes

    def extract(self, stego_image_bytes: bytes) -> bytes:
        """
        Extract hidden bytes from a stego image. O(n)
        Args:
            stego_image_bytes (bytes): PNG image bytes containing hidden data
        Returns:
            bytes: Extracted secret data
        Raises:
            ValueError: If image is not a valid stego image or magic mismatch
        """
        img = Image.open(io.BytesIO(stego_image_bytes)).convert("RGB")
        pixels = list(img.getdata())

        # Extract all bits from LSBs
        bits = []
        for pixel in pixels:
            for ch in pixel[:3]:
                for b in range(self.BITS_PER_CHANNEL - 1, -1, -1):
                    bits.append((ch >> b) & 1)

        def bits_to_bytes(bit_list: list, count: int) -> bytes:
            """Convert bit list to bytes."""
            result = []
            for i in range(count):
                byte_val = 0
                for j in range(8):
                    byte_val = (byte_val << 1) | bit_list[i * 8 + j]
                result.append(byte_val)
            return bytes(result)

        # Read magic (2 bytes = 16 bits)
        magic = bits_to_bytes(bits, len(self.MAGIC))
        if magic != self.MAGIC:
            raise ValueError("Invalid stego image — magic header mismatch. Not a GhostPixel image.")

        offset = len(self.MAGIC)

        # Read length header (4 bytes = 32 bits)
        length_bytes = bits_to_bytes(bits[offset * 8:], self.HEADER_SIZE)
        data_length = struct.unpack(">I", length_bytes)[0]

        offset += self.HEADER_SIZE

        # Validate length
        available_bytes = (len(bits) // 8) - offset
        if data_length > available_bytes:
            raise ValueError(
                f"Corrupted stego image — claimed length {data_length} exceeds available {available_bytes}"
            )

        # Extract the actual data
        secret_data = bits_to_bytes(bits[offset * 8:], data_length)
        return secret_data

    def embed_from_file(self, secret_data: bytes, carrier_path: str, output_path: str) -> str:
        """
        Embed data using a specific carrier image file.
        Args:
            secret_data (bytes): Data to embed
            carrier_path (str): Path to carrier image
            output_path (str): Where to save stego image
        Returns:
            str: Path to stego image
        """
        self.carrier_path = carrier_path
        self.embed(secret_data, output_path)
        return output_path

    @staticmethod
    def image_to_b64(image_bytes: bytes) -> str:
        """Convert image bytes to base64 string for network transmission."""
        return base64.b64encode(image_bytes).decode("utf-8")

    @staticmethod
    def b64_to_image(b64_str: str) -> bytes:
        """Convert base64 string back to image bytes."""
        return base64.b64decode(b64_str)