"""
main.py - GhostPixel Application Entry Point
Launches the Tkinter GUI application.

Usage:
    python main.py

Architecture:
    - Login screen shown on startup
    - On successful auth → Chat screen loads
    - Server starts automatically on chat screen
"""

import tkinter as tk
import sys
import os

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(__file__))

from core.storage import Storage
from core.auth import AuthManager
from gui.login_screen import LoginScreen
from gui.chat_screen import ChatScreen


DARK_BG = "#0a0e1a"
WINDOW_TITLE = "GhostPixel — Hidden in Plain Sight"
WINDOW_SIZE = "1100x720"
MIN_WIDTH = 900
MIN_HEIGHT = 600


class GhostPixelApp:
    """
    Main application controller.
    Manages screen transitions between Login and Chat.
    """

    def __init__(self):
        """Initialize the application."""
        self.root = tk.Tk()
        self.root.title(WINDOW_TITLE)
        self.root.geometry(WINDOW_SIZE)
        self.root.minsize(MIN_WIDTH, MIN_HEIGHT)
        self.root.configure(bg=DARK_BG)

        # Set window icon text (fallback if no icon file)
        try:
            self.root.iconbitmap("assets/icon.ico")
        except Exception:
            pass

        # Initialize backend
        self.storage = Storage()
        self.auth_manager = AuthManager(storage=self.storage)

        self._current_screen = None
        self._show_login()

        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _show_login(self):
        """Display the login screen."""
        self._clear_screen()
        self._current_screen = LoginScreen(
            parent=self.root,
            on_login_success=self._on_login_success,
            storage=self.storage,
            auth_manager=self.auth_manager
        )

    def _on_login_success(self, username: str, session_token: str):
        """Callback when login/register succeeds."""
        self._clear_screen()
        self._current_screen = ChatScreen(
            parent=self.root,
            username=username,
            session_token=session_token,
            auth_manager=self.auth_manager,
            storage=self.storage,
            on_logout=self._show_login
        )

    def _clear_screen(self):
        """Destroy the current screen."""
        if self._current_screen:
            try:
                self._current_screen.destroy()
            except Exception:
                pass
            self._current_screen = None

    def _on_close(self):
        """Handle application close."""
        try:
            if self._current_screen and hasattr(self._current_screen, "client"):
                client = self._current_screen.client
                if client:
                    client.disconnect()
            if self._current_screen and hasattr(self._current_screen, "server"):
                server = self._current_screen.server
                if server:
                    server.stop()
        except Exception:
            pass
        self.root.destroy()

    def run(self):
        """Start the Tkinter main loop."""
        self.root.mainloop()


def main():
    """Application entry point."""
    print("=" * 50)
    print("  GhostPixel | Steganographic E2E Encrypted Messenger")
    print("=" * 50)
    print("Starting GUI...")
    app = GhostPixelApp()
    app.run()


if __name__ == "__main__":
    main()