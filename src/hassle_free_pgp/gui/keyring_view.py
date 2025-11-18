"""Key list widget for displaying and selecting keys."""
import tkinter as tk
from tkinter import ttk, messagebox
from typing import List, Dict, Optional, Callable


class KeyringView(ttk.Frame):
    """Widget for displaying and selecting keys from the keyring."""

    def __init__(self, parent, on_key_select: Optional[Callable] = None,
                 on_delete: Optional[Callable] = None,
                 on_add_public: Optional[Callable] = None):
        """
        Initialize keyring view.

        Args:
            parent: Parent widget
            on_key_select: Optional callback when a key is selected (fingerprint)
            on_delete: Optional callback when delete is requested (fingerprint)
            on_add_public: Optional callback when add public key is requested (fingerprint)
        """
        super().__init__(parent)
        self.on_key_select = on_key_select
        self.on_delete = on_delete
        self.on_add_public = on_add_public
        self.selected_fingerprint = None
        self.key_data = {}  # Store key metadata by item ID

        self.setup_ui()

    def setup_ui(self):
        """Create the UI layout."""
        # Label - Match bottom section header size
        label = ttk.Label(self, text="KEY-RING", font=('Courier New', 13, 'bold'))
        label.pack(pady=5)

        # Treeview for keys
        columns = ('Name', 'Email', 'Fingerprint', 'Options')
        self.tree = ttk.Treeview(self, columns=columns, show='headings', height=10)

        # Configure columns
        self.tree.heading('Name', text='Name')
        self.tree.heading('Email', text='Email')
        self.tree.heading('Fingerprint', text='Fingerprint')
        self.tree.heading('Options', text='⋮')

        self.tree.column('Name', width=150)
        self.tree.column('Email', width=200)
        self.tree.column('Fingerprint', width=150)
        self.tree.column('Options', width=30, anchor='center')

        # Scrollbar
        scrollbar = ttk.Scrollbar(self, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        # Pack widgets
        self.tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')

        # Bind selection event
        self.tree.bind('<<TreeviewSelect>>', self._on_select)

        # Bind right-click for context menu
        self.tree.bind('<Button-2>', self._show_context_menu)  # Right-click on Mac
        self.tree.bind('<Button-3>', self._show_context_menu)  # Right-click on Windows/Linux
        self.tree.bind('<Double-Button-1>', self._on_double_click)  # Double-click for options

    def _on_select(self, event):
        """Handle key selection."""
        selection = self.tree.selection()
        if selection:
            item_id = selection[0]
            if item_id in self.key_data:
                self.selected_fingerprint = self.key_data[item_id]['fingerprint']
                if self.on_key_select:
                    self.on_key_select(self.selected_fingerprint)

    def _on_double_click(self, event):
        """Handle double-click to show options."""
        item = self.tree.identify_row(event.y)
        if item:
            self._show_context_menu(event)

    def _show_context_menu(self, event):
        """Show context menu with options."""
        item = self.tree.identify_row(event.y)
        if not item:
            return

        # Select the item
        self.tree.selection_set(item)

        # Get key info
        key_info = self.key_data.get(item)
        if not key_info:
            return

        # Create context menu
        menu = tk.Menu(self.tree, tearoff=0)

        # Add "Add Public Key" option if key has private but we need to check if public exists
        if key_info.get('has_private'):
            menu.add_command(
                label="📤 Add/Update Public Key",
                command=lambda: self._handle_add_public(key_info['fingerprint'])
            )
            menu.add_separator()

        # Add Delete option
        menu.add_command(
            label="🗑️ Delete Key",
            command=lambda: self._handle_delete(key_info['fingerprint'], key_info['name'])
        )

        # Show menu at cursor position
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _handle_delete(self, fingerprint, name):
        """Handle delete key request."""
        if messagebox.askyesno(
            "Confirm Delete",
                f"Are you sure you want to delete the key '{name}'?\n\nFingerprint: {fingerprint[-16:]}"):
            if self.on_delete:
                self.on_delete(fingerprint)

    def _handle_add_public(self, fingerprint):
        """Handle add public key request."""
        if self.on_add_public:
            self.on_add_public(fingerprint)

    def load_keys(self, keys: List[Dict]):
        """
        Load keys into the view.

        Args:
            keys: List of key dictionaries with 'name', 'email', 'fingerprint'
        """
        # Clear existing items and data
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.key_data.clear()

        # Add keys
        for key_info in keys:
            name = key_info.get('name', '')
            email = key_info.get('email', '')
            fingerprint = key_info.get('fingerprint', '')

            # Show short fingerprint (last 16 chars)
            short_fp = fingerprint[-16:] if len(fingerprint) > 16 else fingerprint

            # Insert into tree and store key data
            item_id = self.tree.insert('', 'end', values=(name, email, short_fp), tags=(fingerprint,))
            self.key_data[item_id] = key_info  # Store the key info for this item!

    def get_selected_fingerprint(self) -> Optional[str]:
        """Get the fingerprint of the currently selected key."""
        return self.selected_fingerprint

    def clear_selection(self):
        """Clear the current selection."""
        self.tree.selection_remove(self.tree.selection())
        self.selected_fingerprint = None
