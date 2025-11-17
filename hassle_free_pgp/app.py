"""Main Tkinter application."""
import logging
import platform
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog
from .gui.keyring_view import KeyringView
from .storage.key_store import KeyStore
from .crypto.keys import (
    ensure_private_key_is_protected,
    export_private_key,
    export_public_key,
    generate_keypair,
    import_key as crypto_import_key,
)
from .crypto.encrypt_decrypt import encrypt_message, decrypt_message
from .crypto.sign_verify import sign_message, verify_signature
from pgpy import PGPKey
from typing import List, Optional
from .colors import COLORS, BUTTON_COLORS


class PGPApplication:
    """Main PGP GUI application."""

    def __init__(self, root):
        """
        Initialize the application.

        Args:
            root: Tkinter root window
        """
        self.root = root
        self.root.title("Hassle Free PGP")
        self.root.geometry("1200x850")

        # Use centralized color configuration
        self.colors = COLORS

        # Configure root window
        self.root.configure(bg=self.colors['bg'])

        # Initialize key store
        self.key_store = KeyStore()

        # Selected keys for operations
        self.selected_public_keys: List[PGPKey] = []
        self.selected_private_key: Optional[PGPKey] = None
        self.selected_private_fingerprint: Optional[str] = None

        # Setup brutalist theme
        self.setup_brutalist_theme()

        # Setup UI
        self.setup_ui()

        # Load keys into keyring view
        self.refresh_keyring()

    def ask_passphrase(self, title="Passphrase", prompt="Enter passphrase:"):
        """
        Show a custom styled passphrase dialog that matches the app design.

        Args:
            title: Dialog title
            prompt: Prompt text

        Returns:
            Passphrase string or None if cancelled
        """
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.geometry("500x200")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(False, False)

        # Configure colors
        dialog.configure(bg=self.colors['bg'])

        result = {'passphrase': None}

        # Main frame
        main_frame = tk.Frame(dialog, bg=self.colors['bg'], padx=30, pady=30)
        main_frame.pack(fill='both', expand=True)

        # Prompt label
        prompt_label = tk.Label(
            main_frame,
            text=prompt,
            font=('Courier New', 12, 'bold'),
            bg=self.colors['bg'],
            fg=self.colors['fg']
        )
        prompt_label.pack(pady=(0, 15))

        # Passphrase entry - BLACK background with WHITE text
        pass_entry = tk.Entry(
            main_frame,
            show='●',
            font=('Courier New', 14),
            bg='#000000',  # Pure black
            fg='#FFFFFF',  # Pure white
            insertbackground='#FFFFFF',  # White cursor
            relief='solid',
            borderwidth=2,
            width=35
        )
        pass_entry.pack(pady=(0, 25), ipady=10)
        pass_entry.focus()

        # Button frame
        button_frame = tk.Frame(main_frame, bg=self.colors['bg'])
        button_frame.pack()

        def on_ok():
            result['passphrase'] = pass_entry.get()
            dialog.destroy()

        def on_cancel():
            result['passphrase'] = None
            dialog.destroy()

        # OK button - BLACK
        ok_btn = tk.Button(
            button_frame,
            text="[ OK ]",
            command=on_ok,
            font=('Courier New', 11, 'bold'),
            bg='#000000',  # Black
            fg='#FFFFFF',  # White text
            activebackground='#333333',  # Dark grey on hover
            activeforeground='#FFFFFF',
            relief='flat',
            padx=30,
            pady=10,
            cursor='hand2'
        )
        ok_btn.pack(side='left', padx=10)

        # Cancel button - BLACK
        cancel_btn = tk.Button(
            button_frame,
            text="[ CANCEL ]",
            command=on_cancel,
            font=('Courier New', 11, 'bold'),
            bg='#000000',  # Black
            fg='#FFFFFF',  # White text
            activebackground='#333333',  # Dark grey on hover
            activeforeground='#FFFFFF',
            relief='flat',
            padx=20,
            pady=10,
            cursor='hand2'
        )
        cancel_btn.pack(side='left', padx=10)

        # Bind Enter key to OK
        pass_entry.bind('<Return>', lambda e: on_ok())
        pass_entry.bind('<Escape>', lambda e: on_cancel())

        # Center the dialog
        dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - (dialog.winfo_width() // 2)
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - (dialog.winfo_height() // 2)
        dialog.geometry(f"+{x}+{y}")

        # Wait for dialog to close
        dialog.wait_window()

        return result['passphrase']

    def setup_brutalist_theme(self):
        """Configure brutalist/minimalist theme."""
        style = ttk.Style()
        style.theme_use('default')

        # Configure colors for all widgets
        style.configure('.',
                        background=self.colors['bg'],
                        foreground=self.colors['fg'],
                        fieldbackground=self.colors['input_bg'],
                        borderwidth=2,
                        relief='flat'
                        )

        # Frame styles
        style.configure('TFrame',
                        background=self.colors['bg'],
                        borderwidth=2,
                        relief='flat'
                        )

        # Label styles
        style.configure('TLabel',
                        background=self.colors['bg'],
                        foreground=self.colors['fg'],
                        font=('Courier New', 10, 'bold')
                        )

        # Button styles - brutalist look
        style.configure('TButton',
                        background=self.colors['button_bg'],
                        foreground=self.colors['button_fg'],
                        borderwidth=2,
                        relief='solid',
                        font=('Courier New', 10, 'bold')
                        )
        style.map('TButton',
                  background=[('active', self.colors['button_active'])],
                  relief=[('pressed', 'sunken')]
                  )

        # LabelFrame styles
        style.configure('TLabelframe',
                        background=self.colors['bg'],
                        foreground=self.colors['fg'],
                        borderwidth=2,
                        relief='solid'
                        )
        style.configure('TLabelframe.Label',
                        background=self.colors['bg'],
                        foreground=self.colors['fg'],
                        font=('Courier New', 10, 'bold')
                        )

        # Treeview (keyring) styles - grey background
        style.configure('Treeview',
                        background=self.colors['input_bg'],
                        foreground=self.colors['fg'],
                        fieldbackground=self.colors['input_bg'],
                        borderwidth=2,
                        relief='solid',
                        font=('Courier New', 11)  # Match bottom section text size
                        )
        style.configure('Treeview.Heading',
                        background=self.colors['bg'],
                        foreground=self.colors['fg'],
                        borderwidth=2,
                        relief='solid',
                        font=('Courier New', 11, 'bold')  # Match bottom section text size
                        )
        style.map('Treeview',
                  background=[('selected', self.colors['button_active'])],
                  foreground=[('selected', self.colors['button_fg'])]
                  )

    def setup_ui(self):
        """Create the GUI layout."""
        # Brutalist menu bar
        menubar = tk.Menu(self.root,
                          bg=self.colors['bg'],
                          fg=self.colors['fg'],
                          activebackground=self.colors['button_active'],
                          activeforeground=self.colors['fg'],
                          borderwidth=2,
                          relief='flat',
                          font=('Courier New', 10, 'bold'))
        self.root.config(menu=menubar)

        # Keys menu
        keys_menu = tk.Menu(menubar, tearoff=0,
                            bg=self.colors['bg'],
                            fg=self.colors['fg'],
                            activebackground=self.colors['button_active'],
                            activeforeground=self.colors['fg'],
                            font=('Courier New', 12))
        keys_menu.add_command(label="CREATE NEW KEY", command=self.create_key_dialog)
        keys_menu.add_command(label="IMPORT KEY", command=self.import_key_dialog)
        keys_menu.add_command(label="EXPORT KEY", command=self.export_key_dialog)
        keys_menu.add_separator()
        keys_menu.add_command(label="REFRESH KEYRING", command=self.refresh_keyring)
        menubar.add_cascade(label="KEYS", menu=keys_menu)

        # Operations menu
        ops_menu = tk.Menu(menubar, tearoff=0,
                           bg=self.colors['bg'],
                           fg=self.colors['fg'],
                           activebackground=self.colors['button_active'],
                           activeforeground=self.colors['fg'],
                           font=('Courier New', 12))
        ops_menu.add_command(label="ENCRYPT", command=self.show_encrypt_view)
        ops_menu.add_command(label="DECRYPT", command=self.show_decrypt_view)
        ops_menu.add_command(label="SIGN", command=self.show_sign_view)
        ops_menu.add_command(label="VERIFY", command=self.show_verify_view)
        menubar.add_cascade(label="OPERATIONS", menu=ops_menu)

        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0,
                            bg=self.colors['bg'],
                            fg=self.colors['fg'],
                            activebackground=self.colors['button_active'],
                            activeforeground=self.colors['fg'],
                            font=('Courier New', 12))
        help_menu.add_command(label="ABOUT", command=self.show_about_dialog)
        menubar.add_cascade(label="HELP", menu=help_menu)

        # Main container - top and bottom sections (50/50 split)
        main_container = tk.Frame(self.root, bg=self.colors['bg'])
        main_container.pack(fill='both', expand=True)

        # Configure 50/50 split
        main_container.rowconfigure(0, weight=1)  # Top section - 50%
        main_container.rowconfigure(1, weight=1)  # Bottom section - 50%
        main_container.columnconfigure(0, weight=1)

        # Top section (keyring + operations)
        top_section = ttk.Frame(main_container)
        top_section.grid(row=0, column=0, sticky='nsew', padx=5, pady=5)

        # Configure grid weights for top section (1:3 ratio)
        top_section.columnconfigure(0, weight=1)  # Keyring - 1/4
        top_section.columnconfigure(1, weight=3)  # Operations - 3/4
        top_section.rowconfigure(0, weight=1)

        # Top-left: Keyring (1/4 width) - Bone white background
        left_panel = tk.Frame(top_section, bg=self.colors['bg'])
        left_panel.grid(row=0, column=0, sticky='nsew', padx=(0, 5))

        # Keyring view
        self.keyring_view = KeyringView(
            left_panel,
            on_key_select=self.on_key_select,
            on_delete=self.delete_key,
            on_add_public=self.add_public_key_dialog
        )
        self.keyring_view.pack(fill='both', expand=True)

        # Keyring status label (aligned right)
        self.keyring_status_var = tk.StringVar(value="[ LOADED 0 KEY(S) ]")
        keyring_status = tk.Label(
            left_panel,
            textvariable=self.keyring_status_var,
            bg=self.colors['bg'],
            fg=self.colors['fg'],
            font=('Courier New', 11, 'bold'),  # Match bottom section text size
            anchor='e',  # Right-aligned
            padx=10,
            pady=5,
            borderwidth=2,
            relief='solid'
        )
        keyring_status.pack(fill='x', side='bottom')

        # Top-right: Operations panel (3/4 width) - WHITE background
        right_panel = tk.Frame(top_section, bg=self.colors['operations_bg'])
        right_panel.grid(row=0, column=1, sticky='nsew')

        # Store reference to right panel for dynamic content
        self.right_panel = right_panel

        # Operation buttons in 2x2 grid (30% smaller with equal spacing)
        operations_button_frame = tk.Frame(right_panel, bg=self.colors['operations_bg'])
        operations_button_frame.pack(fill='both', expand=True, padx=40, pady=40)

        # Configure grid with equal spacing
        # Add empty rows/columns for spacing (15% padding on each side = 30% smaller)
        for i in range(5):
            operations_button_frame.rowconfigure(i, weight=1)
            operations_button_frame.columnconfigure(i, weight=1)

        # Button style - Uses centralized BUTTON_COLORS configuration
        # Commented out unused button_style dictionary
        # button_style = {
        #     'font': ('Courier New', 16, 'bold'),
        #     'bg': BUTTON_COLORS['fill'],
        #     'fg': BUTTON_COLORS['text'],
        #     'activebackground': BUTTON_COLORS['active'],
        #     'activeforeground': BUTTON_COLORS['text'],
        #     'borderwidth': 4,
        #     'relief': 'solid',
        #     'cursor': 'hand2',
        #     'highlightthickness': 4,
        #     'highlightbackground': BUTTON_COLORS['border'],
        #     'highlightcolor': BUTTON_COLORS['border']
        # }

        # Equal spacing between buttons
        button_padding = 15

        # Row 0, Col 0: ENCRYPT (Custom button to fix macOS color bug)
        btn_encrypt = self.create_custom_button(
            operations_button_frame,
            "[ ENCRYPT ]",
            self.show_encrypt_view
        )
        btn_encrypt.grid(row=1, column=1, sticky='nsew', padx=button_padding, pady=button_padding)

        # Row 0, Col 1: DECRYPT (Custom button to fix macOS color bug)
        btn_decrypt = self.create_custom_button(
            operations_button_frame,
            "[ DECRYPT ]",
            self.show_decrypt_view
        )
        btn_decrypt.grid(row=1, column=3, sticky='nsew', padx=button_padding, pady=button_padding)

        # Row 1, Col 0: SIGN (Custom button to fix macOS color bug)
        btn_sign = self.create_custom_button(
            operations_button_frame,
            "[ SIGN ]",
            self.show_sign_view
        )
        btn_sign.grid(row=3, column=1, sticky='nsew', padx=button_padding, pady=button_padding)

        # Row 1, Col 1: VERIFY (Custom button to fix macOS color bug)
        btn_verify = self.create_custom_button(
            operations_button_frame,
            "[ VERIFY ]",
            self.show_verify_view
        )
        btn_verify.grid(row=3, column=3, sticky='nsew', padx=button_padding, pady=button_padding)

        # Store reference to button frame so we can hide it later
        self.operations_button_frame = operations_button_frame

        # Welcome message frame (hidden by default since buttons are visible)
        self.welcome_frame = ttk.Frame(right_panel)
        # Don't pack it - buttons are always visible now

        # Operation header frame (contains back button + operation title)
        self.operation_header_frame = tk.Frame(right_panel, bg=self.colors['operations_bg'])

        # Back button (top left of operations area)
        self.operation_back_button = self.create_small_custom_button(
            self.operation_header_frame,
            "[ ← ]",
            self.show_button_grid
        )
        self.operation_back_button.pack(side='left', padx=5, pady=5)

        # Operation mode label (shown at top when operation is active)
        self.mode_label = tk.Label(self.operation_header_frame,
                                   text="",
                                   font=('Courier New', 12, 'bold'),
                                   fg=self.colors['fg'],
                                   bg=self.colors['operations_bg'],
                                   anchor='w',
                                   padx=10,
                                   pady=5)
        self.mode_label.pack(side='left', fill='x', expand=True)

        # Input area (hidden by default)
        self.input_frame = ttk.LabelFrame(right_panel, text="INPUT")
        self.input_text = scrolledtext.ScrolledText(
            self.input_frame,
            height=15,
            wrap=tk.WORD,
            bg=self.colors['input_bg'],
            fg=self.colors['fg'],
            insertbackground=self.colors['fg'],
            selectbackground=self.colors['button_active'],
            selectforeground=self.colors['fg'],
            font=('Courier New', 10),
            borderwidth=2,
            relief='solid'
        )
        self.input_text.pack(fill='both', expand=True, padx=5, pady=5)

        # Output area (hidden by default)
        self.output_frame = ttk.LabelFrame(right_panel, text="OUTPUT")
        self.output_text = scrolledtext.ScrolledText(
            self.output_frame,
            height=15,
            wrap=tk.WORD,
            bg=self.colors['input_bg'],
            fg=self.colors['fg'],
            insertbackground=self.colors['fg'],
            selectbackground=self.colors['button_active'],
            selectforeground=self.colors['fg'],
            font=('Courier New', 10),
            borderwidth=2,
            relief='solid'
        )
        self.output_text.pack(fill='both', expand=True, padx=5, pady=5)

        # Action buttons frame (hidden by default)
        self.action_frame = ttk.Frame(right_panel)

        # Status bar (brutalist style)
        self.status_var = tk.StringVar(value="[ READY ]")
        status_bar = tk.Label(
            right_panel,
            textvariable=self.status_var,
            bg=self.colors['status_bg'],
            fg=self.colors['fg'],
            font=('Courier New', 9, 'bold'),
            anchor='w',
            padx=10,
            pady=5,
            borderwidth=2,
            relief='solid'
        )
        status_bar.pack(fill='x', side='bottom', padx=0, pady=0)

        # Bottom section - Informational manifesto (50% of screen)
        bottom_section = tk.Frame(main_container,
                                  bg=self.colors['bg'],
                                  relief='solid',
                                  borderwidth=2)
        bottom_section.grid(row=1, column=0, sticky='nsew', padx=5, pady=(0, 5))

        # Create scrollable text area for information
        info_canvas = tk.Canvas(bottom_section,
                                bg=self.colors['bg'],
                                highlightthickness=0,
                                borderwidth=0)
        info_scrollbar = tk.Scrollbar(bottom_section,
                                      orient='vertical',
                                      command=info_canvas.yview,
                                      width=20,
                                      bg=self.colors['input_bg'],
                                      troughcolor=self.colors['bg'])
        info_frame = tk.Frame(info_canvas, bg=self.colors['bg'])

        info_frame.bind(
            "<Configure>",
            lambda e: info_canvas.configure(scrollregion=info_canvas.bbox("all"))
        )

        canvas_window = info_canvas.create_window((0, 0), window=info_frame, anchor='nw')
        info_canvas.configure(yscrollcommand=info_scrollbar.set)

        # Update canvas window width when canvas resizes
        def on_canvas_configure(event):
            info_canvas.itemconfig(canvas_window, width=event.width)
        info_canvas.bind('<Configure>', on_canvas_configure)

        # Mouse wheel scrolling: handle platform differences
        is_macos = platform.system() == "Darwin"
        is_linux = platform.system() == "Linux"

        def on_mousewheel(event):
            # macOS trackpad sends small delta values, Windows sends ±120 per notch
            scroll_amount = -1 * event.delta if is_macos else int(-1 * (event.delta / 120))
            info_canvas.yview_scroll(scroll_amount, "units")

        def bind_mousewheel(event):
            if is_linux:
                info_canvas.bind_all("<Button-4>", lambda e: info_canvas.yview_scroll(-1, "units"))
                info_canvas.bind_all("<Button-5>", lambda e: info_canvas.yview_scroll(1, "units"))
            else:
                info_canvas.bind_all("<MouseWheel>", on_mousewheel)

        def unbind_mousewheel(event):
            if is_linux:
                info_canvas.unbind_all("<Button-4>")
                info_canvas.unbind_all("<Button-5>")
            else:
                info_canvas.unbind_all("<MouseWheel>")

        info_canvas.bind("<Enter>", bind_mousewheel)
        info_canvas.bind("<Leave>", unbind_mousewheel)

        info_canvas.pack(side='left', fill='both', expand=True)
        info_scrollbar.pack(side='right', fill='y')

        # Information text
        self.create_info_section(info_frame)

    def create_custom_button(self, parent, text, command):
        """
        Create a custom button using Frame and Label to avoid macOS color bugs.
        Tkinter buttons on macOS change color when window focus changes.
        """
        # Outer frame for border
        button_frame = tk.Frame(
            parent,
            bg=BUTTON_COLORS['border'],  # Black border
            borderwidth=4,
            relief='solid',
            cursor='hand2'
        )

        # Inner label for content
        button_label = tk.Label(
            button_frame,
            text=text,
            font=('Courier New', 16, 'bold'),
            bg=BUTTON_COLORS['fill'],    # Dark grey fill
            fg=BUTTON_COLORS['text'],    # White text
            padx=20,
            pady=20
        )
        button_label.pack(fill='both', expand=True)

        # Bind click events
        def on_click(event):
            command()

        button_frame.bind('<Button-1>', on_click)
        button_label.bind('<Button-1>', on_click)

        # Visual feedback on hover (optional - keeps color same)
        def on_enter(event):
            button_label.config(bg=BUTTON_COLORS['fill'])

        def on_leave(event):
            button_label.config(bg=BUTTON_COLORS['fill'])

        button_frame.bind('<Enter>', on_enter)
        button_frame.bind('<Leave>', on_leave)
        button_label.bind('<Enter>', on_enter)
        button_label.bind('<Leave>', on_leave)

        return button_frame

    def create_small_custom_button(self, parent, text, command):
        """
        Create a smaller custom button for action areas (BACK, SIGN, etc).
        Uses Frame and Label to avoid macOS color bugs.
        """
        # Outer frame for border
        button_frame = tk.Frame(
            parent,
            bg=BUTTON_COLORS['border'],  # Black border
            borderwidth=2,
            relief='solid',
            cursor='hand2'
        )

        # Inner label for content
        button_label = tk.Label(
            button_frame,
            text=text,
            font=('Courier New', 10, 'bold'),
            bg=BUTTON_COLORS['fill'],    # Dark grey fill
            fg=BUTTON_COLORS['text'],    # White text
            padx=15,
            pady=5
        )
        button_label.pack(fill='both', expand=True)

        # Bind click events
        def on_click(event):
            command()

        button_frame.bind('<Button-1>', on_click)
        button_label.bind('<Button-1>', on_click)

        # Keep consistent colors
        def on_enter(event):
            button_label.config(bg=BUTTON_COLORS['fill'])

        def on_leave(event):
            button_label.config(bg=BUTTON_COLORS['fill'])

        button_frame.bind('<Enter>', on_enter)
        button_frame.bind('<Leave>', on_leave)
        button_label.bind('<Enter>', on_enter)
        button_label.bind('<Leave>', on_leave)

        return button_frame

    def create_info_section(self, parent):
        """Create the informational section at the bottom."""

        # Section 1: How to Use
        how_to_label = tk.Label(parent,
                                text="[ HOW TO USE ]",
                                font=('Courier New', 13, 'bold'),
                                fg=self.colors['fg'],
                                bg=self.colors['bg'],
                                anchor='w')
        how_to_label.pack(fill='x', padx=15, pady=(15, 5))

        how_to_text = tk.Label(
            parent,
            text=(
                "1. CREATE/IMPORT KEYS: Use the KEYS menu to generate new PGP key pairs or import existing keys.\n"
                "2. ENCRYPT: Select OPERATIONS > ENCRYPT to encrypt messages using a recipient's public key.\n"
                "3. DECRYPT: Select OPERATIONS > DECRYPT to decrypt messages using your private key and passphrase.\n"
                "4. SIGN: Select OPERATIONS > SIGN to cryptographically sign messages with your private key.\n"
                "5. VERIFY: Select OPERATIONS > VERIFY to verify signed messages using the sender's public key.\n"
                "6. MANAGE: Right-click keys in the keyring to delete or add/update public keys."),
            font=(
                'Courier New',
                11),
            fg=self.colors['text_dark_grey'],
            bg=self.colors['bg'],
            justify='left',
            anchor='w')
        how_to_text.pack(fill='x', padx=15, pady=5)

        # Section 2: Why PGP Matters
        why_label = tk.Label(parent,
                             text="[ WHY PGP MATTERS IN THE DYING FREE INTERNET ]",
                             font=('Courier New', 13, 'bold'),
                             fg=self.colors['fg'],
                             bg=self.colors['bg'],
                             anchor='w')
        why_label.pack(fill='x', padx=15, pady=(15, 5))

        why_text = tk.Label(
            parent, text=(
                "The internet was built on principles of freedom, privacy, and decentralization. Today, these\n"
                "principles are under constant assault. Mass surveillance, corporate data harvesting, and\n"
                "government overreach threaten our fundamental right to private communication. PGP (Pretty Good\n"
                "Privacy) represents one of the last bastions of truly private, encrypted communication that\n"
                "cannot be intercepted, backdoored, or compromised by third parties.\n\n"
                "Unlike proprietary messaging apps that can be compelled to hand over data or implement\n"
                "backdoors, PGP is:\n"
                "  • END-TO-END ENCRYPTED: Only you and your intended recipient can read the message.\n"
                "  • MATHEMATICALLY SECURE: Based on proven cryptographic principles, not corporate promises.\n"
                "  • DECENTRALIZED: No central server, no company to shut down, no single point of failure.\n"
                "  • OPEN SOURCE: Transparent, auditable code that anyone can verify and trust.\n"
                "  • YOURS TO CONTROL: Your keys, your data, your privacy. No one else has access.\n\n"
                "In an era where privacy is treated as a product to be sold rather than a right to be\n"
                "protected, PGP empowers individuals to take back control of their communications. It's not\n"
                "just about having something to hide—it's about preserving the fundamental human right to\n"
                "privacy in digital spaces."), font=(
                'Courier New', 11), fg=self.colors['text_dark_grey'], bg=self.colors['bg'], justify='left', anchor='w')
        why_text.pack(fill='x', padx=15, pady=5)

        # Section 3: Open Source Libraries
        tech_label = tk.Label(parent,
                              text="[ OPEN SOURCE PGP LIBRARIES & RESOURCES ]",
                              font=('Courier New', 13, 'bold'),
                              fg=self.colors['fg'],
                              bg=self.colors['bg'],
                              anchor='w')
        tech_label.pack(fill='x', padx=15, pady=(15, 5))

        tech_text = tk.Label(
            parent, text=(
                "This application is built on open source software that you can audit, verify, and trust:\n\n"
                "• PGPy (https://github.com/SecurityInnovation/PGPy)\n"
                "  Pure Python implementation of OpenPGP. No binary dependencies, fully auditable.\n"
                "  License: BSD 3-Clause. Actively maintained and security-focused.\n\n"
                "• GnuPG (https://gnupg.org)\n"
                "  The gold standard for PGP encryption. Free, open source, and trusted worldwide.\n"
                "  License: GPL. Used by journalists, activists, and security professionals.\n\n"
                "• OpenPGP Standard (https://www.openpgp.org)\n"
                "  RFC 4880 - The official specification for PGP encryption.\n"
                "  Open standard ensures interoperability across all implementations.\n\n"
                "• ProtonMail (https://protonmail.com)\n"
                "  Email service with built-in PGP encryption. Switzerland-based, privacy-focused.\n\n"
                "• Keybase (https://keybase.io)\n"
                "  Public key infrastructure with PGP support and identity verification.\n\n"
                "REMEMBER: The strength of PGP lies not just in its mathematics, but in its openness.\n"
                "Always verify the source code. Never trust closed-source encryption. Stay vigilant.\n"
                "The free internet depends on tools like these—and people like you who use them."), font=(
                'Courier New', 11), fg=self.colors['text_dark_grey'], bg=self.colors['bg'], justify='left', anchor='w')
        tech_text.pack(fill='x', padx=15, pady=(5, 15))

    def refresh_keyring(self):
        """Refresh the keyring view with current keys."""
        keys = self.key_store.list_keys()
        self.keyring_view.load_keys(keys)
        self.keyring_status_var.set(f"[ LOADED {len(keys)} KEY(S) ]")

    def report_error(self, context: str, error: Exception):
        """Log errors and surface them in the status bar."""
        message = f"[ ERROR ] {context}: {error}"
        logging.error(message)
        if hasattr(self, 'status_var'):
            self.status_var.set(message)

    def on_key_select(self, fingerprint: str):
        """Handle key selection from keyring."""
        # This will be used when selecting keys for operations
        pass

    def delete_key(self, fingerprint: str):
        """Delete a key from the keyring."""
        try:
            self.key_store.remove_key(fingerprint)
            self.refresh_keyring()
            self.status_var.set("[ KEY DELETED ]")
        except Exception as exc:
            self.report_error("Failed to delete key", exc)

    def add_public_key_dialog(self, fingerprint: str):
        """Show dialog to add/update public key for a private key."""
        dialog = tk.Toplevel(self.root)
        dialog.title("Add/Update Public Key")
        dialog.geometry("550x400")
        dialog.transient(self.root)
        dialog.grab_set()

        # Get the key info
        keys = self.key_store.list_keys()
        key_info = None
        for k in keys:
            if k['fingerprint'] == fingerprint:
                key_info = k
                break

        if not key_info:
            pass  # messagebox popup removed
            dialog.destroy()
            return

        ttk.Label(
            dialog,
            text=f"Add/Update Public Key for: {key_info['name']}",
            font=('Arial', 11, 'bold')
        ).pack(pady=10)

        ttk.Label(
            dialog,
            text="Paste the PUBLIC key (someone can use this to encrypt messages to you):",
            wraplength=500
        ).pack(pady=5)

        key_text = scrolledtext.ScrolledText(dialog, height=15, width=60)
        key_text.pack(pady=5, padx=10, fill='both', expand=True)

        # Try to auto-fill with existing public key
        try:
            existing_key = self.key_store.get_key(fingerprint, private=False)
            if existing_key:
                key_text.insert('1.0', export_public_key(existing_key))
                key_text.config(state='disabled')
                ttk.Label(dialog, text="Public key already exists (shown above)", foreground='green').pack(pady=5)
        except BaseException:
            pass

        def import_public():
            armored_key = key_text.get('1.0', tk.END).strip()

            if not armored_key:
                pass  # messagebox popup removed
                return

            try:
                key = crypto_import_key(armored_key, None)

                # Verify it matches the fingerprint
                if str(key.fingerprint).replace(' ', '') != fingerprint:
                    pass  # messagebox popup removed
                    return

                # Update the key store (it will add/update the public key)
                self.key_store.add_key(key, key_info['name'], key_info['email'])
                self.refresh_keyring()
                dialog.destroy()
                pass  # messagebox popup removed
            except Exception as exc:
                self.report_error("Failed to import public key", exc)
        if key_text.cget('state') != 'disabled':
            ttk.Button(dialog, text="Add Public Key", command=import_public).pack(pady=10)
        else:
            ttk.Button(dialog, text="Close", command=dialog.destroy).pack(pady=10)

    def create_key_dialog(self):
        """Show dialog to create a new key."""
        dialog = tk.Toplevel(self.root)
        dialog.title("Generate PGP Keys")
        dialog.geometry("700x700")
        dialog.transient(self.root)
        dialog.grab_set()

        # Main frame with padding
        main_frame = ttk.Frame(dialog, padding="20")
        main_frame.pack(fill='both', expand=True)

        # Title
        ttk.Label(main_frame, text="Generate PGP Keys", font=('Arial', 14, 'bold')).pack(pady=(0, 20))

        # Key Label field
        name_frame = ttk.Frame(main_frame)
        name_frame.pack(fill='x', pady=5)
        ttk.Label(name_frame, text="Key Label:", width=20, anchor='w').pack(side='left')
        ttk.Label(name_frame, text="(Required)", foreground='red', font=('Arial', 9)).pack(side='left', padx=5)
        name_entry = ttk.Entry(main_frame, width=50)
        name_entry.pack(fill='x', pady=(0, 5))
        ttk.Label(main_frame, text="e.g., 'My Work Key', 'Personal', 'Trading Account'",
                  foreground='gray', font=('Arial', 9)).pack(anchor='w', pady=(0, 10))

        # Email field
        email_frame = ttk.Frame(main_frame)
        email_frame.pack(fill='x', pady=5)
        ttk.Label(email_frame, text="Email address:", width=20, anchor='w').pack(side='left')
        ttk.Label(email_frame, text="(Optional)", foreground='gray', font=('Arial', 9)).pack(side='left', padx=5)
        email_entry = ttk.Entry(main_frame, width=50)
        email_entry.pack(fill='x', pady=(0, 5))
        ttk.Label(main_frame, text="Only needed if using with email. Otherwise skip.",
                  foreground='gray', font=('Arial', 9)).pack(anchor='w', pady=(0, 10))

        # Password field
        ttk.Label(main_frame, text="Choose a password:", anchor='w').pack(fill='x', pady=5)
        passphrase_entry = ttk.Entry(main_frame, width=50, show='*')
        passphrase_entry.pack(fill='x', pady=(0, 10))

        # Key size dropdown
        ttk.Label(main_frame, text="Key Size:", anchor='w').pack(fill='x', pady=5)
        key_size_var = tk.StringVar(value="4096 bits - recommended")
        key_size_combo = ttk.Combobox(main_frame, textvariable=key_size_var, state='readonly', width=47)
        key_size_combo['values'] = ("4096 bits - recommended", "2048 bits")
        key_size_combo.pack(fill='x', pady=(0, 10))

        # Info label
        ttk.Label(main_frame, text="Your browser may not respond during key generation.",
                  foreground='gray', font=('Arial', 9)).pack(pady=10)

        # Generated keys display area
        keys_frame = ttk.Frame(main_frame)
        keys_frame.pack(fill='both', expand=True, pady=10)

        # Public key display
        ttk.Label(keys_frame, text="Public Key", font=('Arial', 10, 'bold')).pack(anchor='w', pady=5)
        public_key_text = scrolledtext.ScrolledText(keys_frame, height=8, width=70, state='disabled')
        public_key_text.pack(fill='both', expand=True, pady=(0, 10))

        # Private key display
        ttk.Label(keys_frame, text="Private Key", font=('Arial', 10, 'bold')).pack(anchor='w', pady=5)
        private_key_text = scrolledtext.ScrolledText(keys_frame, height=8, width=70, state='disabled')
        private_key_text.pack(fill='both', expand=True)

        # Status label
        status_label = ttk.Label(main_frame, text="", foreground='green', font=('Arial', 10))
        status_label.pack(pady=5)

        def create_key():
            name = name_entry.get().strip()
            email = email_entry.get().strip() or 'noemail@local'  # Default if empty
            passphrase = passphrase_entry.get()

            if not name:
                pass  # messagebox popup removed
                return

            if not passphrase:
                pass  # messagebox popup removed
                return

            # Get key size
            key_size = 4096 if "4096" in key_size_var.get() else 2048

            try:
                # Show generating status
                status_label.config(
                    text=f"Generating {key_size}-bit RSA keypair... Please wait...",
                    foreground='orange')
                dialog.update()

                key = generate_keypair(name=name, email=email, passphrase=passphrase, key_size=key_size)

                # Export keys
                public_key_armored = export_public_key(key)
                private_key_armored = export_private_key(key)

                # Display keys
                public_key_text.config(state='normal')
                public_key_text.delete('1.0', tk.END)
                public_key_text.insert('1.0', public_key_armored)
                public_key_text.config(state='disabled')

                private_key_text.config(state='normal')
                private_key_text.delete('1.0', tk.END)
                private_key_text.insert('1.0', private_key_armored)
                private_key_text.config(state='disabled')

                # Save to keyring
                self.key_store.add_key(key, name, email)
                self.refresh_keyring()

                status_label.config(text="✓ Keys generated and saved successfully!", foreground='green')

                # Add copy buttons
                button_frame = ttk.Frame(main_frame)
                button_frame.pack(pady=10)

                def copy_public():
                    dialog.clipboard_clear()
                    dialog.clipboard_append(public_key_armored)
                    pass  # messagebox popup removed

                def copy_private():
                    dialog.clipboard_clear()
                    dialog.clipboard_append(private_key_armored)
                    pass  # messagebox popup removed
                ttk.Button(button_frame, text="Copy Public Key", command=copy_public).pack(side='left', padx=5)
                ttk.Button(button_frame, text="Copy Private Key", command=copy_private).pack(side='left', padx=5)
                ttk.Button(button_frame, text="Close", command=dialog.destroy).pack(side='left', padx=5)

            except Exception:
                status_label.config(text="", foreground='green')
                pass  # messagebox popup removed
        # Generate button
        ttk.Button(main_frame, text="Generate PGP Keys", command=create_key,
                   style='Accent.TButton').pack(pady=10)

    def import_key_dialog(self):
        """Show dialog to import a key."""
        dialog = tk.Toplevel(self.root)
        dialog.title("Import Key")
        dialog.geometry("650x550")
        dialog.transient(self.root)
        dialog.grab_set()

        # Create notebook for tabs
        notebook = ttk.Notebook(dialog)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)

        # Tab 1: Paste Private Key
        private_frame = ttk.Frame(notebook)
        notebook.add(private_frame, text="Import Private Key")

        ttk.Label(private_frame, text="Paste ASCII-armored PRIVATE key:", font=('Arial', 10, 'bold')).pack(pady=5)
        private_key_text = scrolledtext.ScrolledText(private_frame, height=12, width=70)
        private_key_text.pack(pady=5, padx=10, fill='both', expand=True)

        # Name field
        name_frame = ttk.Frame(private_frame)
        name_frame.pack(fill='x', padx=10, pady=5)
        ttk.Label(name_frame, text="Name (label for this key):").pack(side='left', padx=5)
        private_name_entry = ttk.Entry(name_frame, width=30)
        private_name_entry.pack(side='left', padx=5, fill='x', expand=True)

        # Email field
        email_frame = ttk.Frame(private_frame)
        email_frame.pack(fill='x', padx=10, pady=5)
        ttk.Label(email_frame, text="Email (optional):").pack(side='left', padx=5)
        private_email_entry = ttk.Entry(email_frame, width=30)
        private_email_entry.pack(side='left', padx=5, fill='x', expand=True)

        # Passphrase field
        pass_frame = ttk.Frame(private_frame)
        pass_frame.pack(fill='x', padx=10, pady=5)
        ttk.Label(pass_frame, text="Passphrase:").pack(side='left', padx=5)
        private_passphrase_entry = ttk.Entry(pass_frame, width=30, show='*')
        private_passphrase_entry.pack(side='left', padx=5, fill='x', expand=True)

        def import_private():
            armored_key = private_key_text.get('1.0', tk.END).strip()
            passphrase = private_passphrase_entry.get().strip() or None
            name = private_name_entry.get().strip()
            email = private_email_entry.get().strip()

            if not armored_key:
                pass  # messagebox popup removed
                return

            if not name:
                pass  # messagebox popup removed
                return

            try:
                key = crypto_import_key(armored_key, passphrase)

                if not key.is_public and not key.is_protected:
                    protection_passphrase = passphrase or self.ask_passphrase(
                        title="Protect Imported Private Key",
                        prompt="This private key is unprotected. Enter a passphrase to secure it:")
                    ensure_private_key_is_protected(key, protection_passphrase)

                # If email not provided, try to extract from key
                if not email and key.userids:
                    uid = key.userids[0]
                    email = uid.email or ''

                self.key_store.add_key(key, name, email)
                self.refresh_keyring()
                dialog.destroy()
                pass  # messagebox popup removed
            except Exception as exc:
                self.report_error("Failed to import private key", exc)
        ttk.Button(private_frame, text="Import Private Key", command=import_private).pack(pady=10)

        # Tab 2: Paste Public Key
        public_frame = ttk.Frame(notebook)
        notebook.add(public_frame, text="Import Public Key")

        ttk.Label(public_frame, text="Paste ASCII-armored PUBLIC key:", font=('Arial', 10, 'bold')).pack(pady=5)
        public_key_text = scrolledtext.ScrolledText(public_frame, height=12, width=70)
        public_key_text.pack(pady=5, padx=10, fill='both', expand=True)

        # Name field for public key
        pub_name_frame = ttk.Frame(public_frame)
        pub_name_frame.pack(fill='x', padx=10, pady=5)
        ttk.Label(pub_name_frame, text="Name (label for this key):").pack(side='left', padx=5)
        public_name_entry = ttk.Entry(pub_name_frame, width=30)
        public_name_entry.pack(side='left', padx=5, fill='x', expand=True)

        # Email field for public key
        pub_email_frame = ttk.Frame(public_frame)
        pub_email_frame.pack(fill='x', padx=10, pady=5)
        ttk.Label(pub_email_frame, text="Email (optional):").pack(side='left', padx=5)
        public_email_entry = ttk.Entry(pub_email_frame, width=30)
        public_email_entry.pack(side='left', padx=5, fill='x', expand=True)

        def import_public():
            armored_key = public_key_text.get('1.0', tk.END).strip()
            name = public_name_entry.get().strip()
            email = public_email_entry.get().strip()

            if not armored_key:
                pass  # messagebox popup removed
                return

            if not name:
                pass  # messagebox popup removed
                return

            try:
                key = crypto_import_key(armored_key, None)

                # If email not provided, try to extract from key
                if not email and key.userids:
                    uid = key.userids[0]
                    email = uid.email or ''

                self.key_store.add_key(key, name, email)
                self.refresh_keyring()
                dialog.destroy()
                pass  # messagebox popup removed
            except Exception as exc:
                self.report_error("Failed to import public key", exc)
        ttk.Button(public_frame, text="Import Public Key", command=import_public).pack(pady=10)

        # Tab 3: Load from File
        file_frame = ttk.Frame(notebook)
        notebook.add(file_frame, text="Load from File")

        ttk.Label(file_frame, text="Load key from a file:", font=('Arial', 10, 'bold')).pack(pady=20)

        selected_file = tk.StringVar(value="No file selected")
        ttk.Label(file_frame, textvariable=selected_file, foreground='gray').pack(pady=10)

        # Name field for file import
        file_name_frame = ttk.Frame(file_frame)
        file_name_frame.pack(fill='x', padx=10, pady=10)
        ttk.Label(file_name_frame, text="Name (label for this key):").pack(side='left', padx=5)
        file_name_entry = ttk.Entry(file_name_frame, width=30)
        file_name_entry.pack(side='left', padx=5, fill='x', expand=True)

        # Passphrase for file import
        file_pass_frame = ttk.Frame(file_frame)
        file_pass_frame.pack(fill='x', padx=10, pady=5)
        ttk.Label(file_pass_frame, text="Passphrase (if private key):").pack(side='left', padx=5)
        file_passphrase_entry = ttk.Entry(file_pass_frame, width=30, show='*')
        file_passphrase_entry.pack(side='left', padx=5, fill='x', expand=True)

        def select_file():
            filename = filedialog.askopenfilename(
                title="Select PGP Key File",
                filetypes=[
                    ("PGP Key Files", "*.asc *.pgp *.gpg"),
                    ("Text Files", "*.txt"),
                    ("All Files", "*.*")
                ]
            )
            if filename:
                selected_file.set(filename)
                # Auto-fill name from filename
                import os
                basename = os.path.basename(filename)
                file_name_entry.delete(0, tk.END)
                file_name_entry.insert(0, basename.rsplit('.', 1)[0])

        def import_from_file():
            filepath = selected_file.get()
            if filepath == "No file selected":
                pass  # messagebox popup removed
                return

            name = file_name_entry.get().strip()
            passphrase = file_passphrase_entry.get().strip() or None

            if not name:
                pass  # messagebox popup removed
                return

            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    armored_key = f.read()

                key = crypto_import_key(armored_key, passphrase)

                if not key.is_public and not key.is_protected:
                    protection_passphrase = passphrase or self.ask_passphrase(
                        title="Protect Imported Private Key",
                        prompt="This private key is unprotected. Enter a passphrase to secure it:")
                    ensure_private_key_is_protected(key, protection_passphrase)

                # Extract email from key if available
                email = ''
                if key.userids:
                    uid = key.userids[0]
                    email = uid.email or ''

                self.key_store.add_key(key, name, email)
                self.refresh_keyring()
                dialog.destroy()
                pass  # messagebox popup removed
            except Exception as exc:
                self.report_error("Failed to import key from file", exc)
        ttk.Button(file_frame, text="Select File...", command=select_file).pack(pady=10)
        ttk.Button(file_frame, text="Import from File", command=import_from_file).pack(pady=10)

    def export_key_dialog(self):
        """Show dialog to export a key."""
        fingerprint = self.keyring_view.get_selected_fingerprint()
        if not fingerprint:
            pass  # messagebox popup removed
            return

        # Get full fingerprint from metadata
        keys = self.key_store.list_keys()
        full_fingerprint = None
        for key_info in keys:
            if key_info.get('fingerprint', '').endswith(fingerprint):
                full_fingerprint = key_info.get('fingerprint')
                break

        if not full_fingerprint:
            pass  # messagebox popup removed
            return

        dialog = tk.Toplevel(self.root)
        dialog.title("Export Key")
        dialog.geometry("400x150")
        dialog.transient(self.root)
        dialog.grab_set()

        def export_public():
            try:
                key = self.key_store.get_key(full_fingerprint, private=False)
                if not key:
                    pass  # messagebox popup removed
                    return

                armored = export_public_key(key)

                # Show in output area
                self.output_text.delete('1.0', tk.END)
                self.output_text.insert('1.0', armored)
                self.mode_label.config(text="Public Key Export")
                dialog.destroy()
                pass  # messagebox popup removed
            except Exception as exc:
                self.report_error("Failed to export public key", exc)

        def export_private():
            passphrase = self.ask_passphrase("Passphrase Required", "Enter passphrase to protect exported key:")
            if not passphrase:
                return

            try:
                key = self.key_store.get_key(full_fingerprint, private=True)
                if not key:
                    pass  # messagebox popup removed
                    return

                armored = export_private_key(key, passphrase)

                # Show in output area
                self.output_text.delete('1.0', tk.END)
                self.output_text.insert('1.0', armored)
                self.mode_label.config(text="Private Key Export")
                dialog.destroy()
                pass  # messagebox popup removed
            except Exception as exc:
                self.report_error("Failed to export private key", exc)
        ttk.Button(dialog, text="Export Public Key", command=export_public).pack(pady=10)
        ttk.Button(dialog, text="Export Private Key", command=export_private).pack(pady=10)

    def show_encrypt_view(self):
        """Show encryption view - opens a new clean dialog."""
        dialog = tk.Toplevel(self.root)
        dialog.title("Encrypt a Message")
        dialog.geometry("700x700")
        dialog.transient(self.root)
        dialog.grab_set()

        # Main frame
        main_frame = ttk.Frame(dialog, padding="20")
        main_frame.pack(fill='both', expand=True)

        # Title
        ttk.Label(main_frame, text="Encrypt a Message", font=('Arial', 14, 'bold')).pack(pady=(0, 20))

        # Your message
        ttk.Label(main_frame, text="Your message:", anchor='w').pack(fill='x', pady=5)
        message_text = scrolledtext.ScrolledText(main_frame, height=10, width=70)
        message_text.pack(fill='both', expand=True, pady=(0, 15))

        # Public key input
        ttk.Label(main_frame, text="The public key to encrypt to:", anchor='w').pack(fill='x', pady=5)
        public_key_text = scrolledtext.ScrolledText(main_frame, height=10, width=70)
        public_key_text.pack(fill='both', expand=True, pady=(0, 15))

        # Encrypted message output (initially hidden)
        output_label = ttk.Label(main_frame, text="Encrypted message:", anchor='w', font=('Arial', 10, 'bold'))
        encrypted_output = scrolledtext.ScrolledText(main_frame, height=10, width=70, state='disabled')

        def encrypt():
            plaintext = message_text.get('1.0', tk.END).strip()
            public_key_armored = public_key_text.get('1.0', tk.END).strip()

            if not plaintext:
                pass  # messagebox popup removed
                return

            if not public_key_armored:
                pass  # messagebox popup removed
                return

            try:
                # Import the public key
                recipient_key = crypto_import_key(public_key_armored, None)

                # Encrypt the message
                encrypted = encrypt_message(plaintext, [recipient_key])

                # Show encrypted message
                output_label.pack(fill='x', pady=(10, 5))
                encrypted_output.pack(fill='both', expand=True, pady=(0, 10))

                encrypted_output.config(state='normal')
                encrypted_output.delete('1.0', tk.END)
                encrypted_output.insert('1.0', encrypted)
                encrypted_output.config(state='disabled')

                # Add copy button
                def copy_encrypted():
                    dialog.clipboard_clear()
                    dialog.clipboard_append(encrypted)
                    pass  # messagebox popup removed
                copy_btn = ttk.Button(main_frame, text="Copy Encrypted Message", command=copy_encrypted)
                copy_btn.pack(pady=5)

                pass  # messagebox popup removed
            except Exception as exc:
                self.report_error("Failed to encrypt message", exc)
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=10)

        ttk.Button(button_frame, text="Encrypt", command=encrypt).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Close", command=dialog.destroy).pack(side='left', padx=5)

    def show_decrypt_view(self):
        """Show decryption view - opens a new clean dialog."""
        dialog = tk.Toplevel(self.root)
        dialog.title("Decrypt a Message")
        dialog.geometry("700x600")
        dialog.transient(self.root)
        dialog.grab_set()

        # Main frame
        main_frame = ttk.Frame(dialog, padding="20")
        main_frame.pack(fill='both', expand=True)

        # Title
        ttk.Label(main_frame, text="Decrypt a Message", font=('Arial', 14, 'bold')).pack(pady=(0, 20))

        # Key selector
        ttk.Label(main_frame, text="Select your private key:", anchor='w').pack(fill='x', pady=5)

        # Get private keys
        all_keys = self.key_store.list_keys()
        private_keys = [k for k in all_keys if k.get('has_private', False)]

        if not private_keys:
            pass  # messagebox popup removed
            dialog.destroy()
            return

        key_options = [f"{k['name']} <{k['email']}>" for k in private_keys]
        selected_key_var = tk.StringVar(value=key_options[0] if key_options else "")
        key_combo = ttk.Combobox(main_frame, textvariable=selected_key_var, state='readonly', width=60)
        key_combo['values'] = key_options
        key_combo.pack(fill='x', pady=(0, 15))

        # Password field
        ttk.Label(main_frame, text="Your password:", anchor='w').pack(fill='x', pady=5)
        passphrase_entry = ttk.Entry(main_frame, width=50, show='*')
        passphrase_entry.pack(fill='x', pady=(0, 15))

        # Encrypted message
        ttk.Label(main_frame, text="Your encrypted message:", anchor='w').pack(fill='x', pady=5)
        encrypted_text = scrolledtext.ScrolledText(main_frame, height=12, width=70)
        encrypted_text.pack(fill='both', expand=True, pady=(0, 15))

        # Decrypted message output (initially hidden)
        output_label = ttk.Label(main_frame, text="Decrypted message:", anchor='w', font=('Arial', 10, 'bold'))
        decrypted_text = scrolledtext.ScrolledText(main_frame, height=8, width=70, state='disabled')

        def decrypt():
            ciphertext = encrypted_text.get('1.0', tk.END).strip()
            passphrase = passphrase_entry.get().strip()

            if not ciphertext:
                pass  # messagebox popup removed
                return

            if not passphrase:
                pass  # messagebox popup removed
                return

            # Get selected key
            selected_index = key_combo.current()
            if selected_index < 0:
                pass  # messagebox popup removed
                return

            selected_key_info = private_keys[selected_index]
            fingerprint = selected_key_info['fingerprint']

            try:
                private_key = self.key_store.get_key(fingerprint, private=True)
                if not private_key:
                    pass  # messagebox popup removed
                    return

                plaintext, metadata = decrypt_message(ciphertext, private_key, passphrase)

                # Clear passphrase from memory
                passphrase = None
                passphrase_entry.delete(0, tk.END)

                # Format the plaintext - handle escape sequences
                formatted_plaintext = plaintext.replace(
                    '\\r\\n',
                    '\n').replace(
                    '\\n',
                    '\n').replace(
                    '\\r',
                    '\n').replace(
                    '\\t',
                    '\t')

                # Show decrypted message
                output_label.pack(fill='x', pady=(10, 5))
                decrypted_text.pack(fill='both', expand=True, pady=(0, 10))

                decrypted_text.config(state='normal')
                decrypted_text.delete('1.0', tk.END)
                decrypted_text.insert('1.0', formatted_plaintext)

                if metadata:
                    meta_str = "\n\n--- Metadata ---\n"
                    for key, value in metadata.items():
                        meta_str += f"{key}: {value}\n"
                    decrypted_text.insert(tk.END, meta_str)

                decrypted_text.config(state='disabled')

                pass  # messagebox popup removed
            except Exception as exc:
                self.report_error("Failed to decrypt message", exc)
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=10)

        ttk.Button(button_frame, text="Decrypt a Message", command=decrypt).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Close", command=dialog.destroy).pack(side='left', padx=5)

    def show_button_grid(self):
        """Show the operation button grid and hide work area."""
        self.operation_header_frame.pack_forget()
        self.input_frame.pack_forget()
        self.output_frame.pack_forget()
        self.action_frame.pack_forget()
        self.operations_button_frame.pack(fill='both', expand=True, padx=10, pady=10)

    def show_work_area(self):
        """Show the input/output work area and hide button grid."""
        self.operations_button_frame.pack_forget()
        self.operation_header_frame.pack(fill='x', padx=5, pady=5)
        self.input_frame.pack(fill='both', expand=True, padx=5, pady=5)
        self.output_frame.pack(fill='both', expand=True, padx=5, pady=5)
        self.action_frame.pack(fill='x', padx=5, pady=5)

        # Add a back button to return to button grid (custom button to fix macOS color bug)
        if not hasattr(self, 'back_button'):
            self.back_button = self.create_small_custom_button(
                self.action_frame,
                "[ ← BACK ]",
                self.show_button_grid
            )
        self.back_button.pack(side='right', padx=5)

    def show_sign_view(self):
        """Show signing view."""
        self.show_work_area()
        self.mode_label.config(text="[ SIGN MESSAGE ]")
        self.clear_action_buttons()

        # Clear output
        self.output_text.delete('1.0', tk.END)

        def sign():
            message = self.input_text.get('1.0', tk.END).strip()
            if not message:
                pass  # messagebox popup removed
                return

            # Get selected private key
            fingerprint = self.keyring_view.get_selected_fingerprint()
            if not fingerprint:
                pass  # messagebox popup removed
                return

            # Get full fingerprint
            keys = self.key_store.list_keys()
            full_fingerprint = None
            for key_info in keys:
                if key_info.get('fingerprint', '').endswith(fingerprint):
                    full_fingerprint = key_info.get('fingerprint')
                    if not key_info.get('has_private', False):
                        pass  # messagebox popup removed
                        return
                    break

            if not full_fingerprint:
                pass  # messagebox popup removed
                return

            # Prompt for passphrase
            passphrase = self.ask_passphrase("Passphrase Required", "Enter passphrase for private key:")
            if not passphrase:
                return

            try:
                private_key = self.key_store.get_key(full_fingerprint, private=True)
                if not private_key:
                    pass  # messagebox popup removed
                    return

                signature = sign_message(message, private_key, passphrase, detached=True)

                # Clear passphrase from memory
                passphrase = None

                self.output_text.delete('1.0', tk.END)
                self.output_text.insert('1.0', signature)
                self.status_var.set("[ MESSAGE SIGNED ]")
            except Exception as exc:
                self.report_error("Failed to sign message", exc)
        # Custom button to fix macOS color bug
        sign_btn = self.create_small_custom_button(
            self.action_frame,
            "[ SIGN ]",
            sign
        )
        sign_btn.pack(side='left', padx=5)

    def show_verify_view(self):
        """Show verification view - opens a new clean dialog."""
        dialog = tk.Toplevel(self.root)
        dialog.title("Verify Signature")
        dialog.geometry("700x650")
        dialog.transient(self.root)
        dialog.grab_set()

        # Main frame
        main_frame = ttk.Frame(dialog, padding="20")
        main_frame.pack(fill='both', expand=True)

        # Title
        ttk.Label(main_frame, text="Verify Signature", font=('Arial', 14, 'bold')).pack(pady=(0, 20))

        # Key selector
        ttk.Label(main_frame, text="Select the signer's public key:", anchor='w').pack(fill='x', pady=5)

        # Get all keys (public and private, but we'll use public portion)
        all_keys = self.key_store.list_keys()

        if not all_keys:
            pass  # messagebox popup removed
            dialog.destroy()
            return

        key_options = [f"{k['name']} <{k['email']}> [{k['fingerprint'][-16:]}]" for k in all_keys]
        selected_key_var = tk.StringVar(value=key_options[0] if key_options else "")
        key_combo = ttk.Combobox(main_frame, textvariable=selected_key_var, state='readonly', width=60)
        key_combo['values'] = key_options
        key_combo.pack(fill='x', pady=(0, 15))

        # Signed message input
        ttk.Label(main_frame, text="Signed message:", anchor='w').pack(fill='x', pady=5)
        signed_text = scrolledtext.ScrolledText(main_frame, height=12, width=70)
        signed_text.pack(fill='both', expand=True, pady=(0, 15))

        # Verification result output (initially hidden)
        result_label = ttk.Label(main_frame, text="Verification result:", anchor='w', font=('Arial', 10, 'bold'))
        result_text = scrolledtext.ScrolledText(main_frame, height=10, width=70, state='disabled')

        def verify():
            input_content = signed_text.get('1.0', tk.END).strip()

            if not input_content:
                pass  # messagebox popup removed
                return

            # Get selected key
            selected_index = key_combo.current()
            if selected_index < 0:
                pass  # messagebox popup removed
                return

            selected_key_info = all_keys[selected_index]
            fingerprint = selected_key_info['fingerprint']

            try:
                public_key = self.key_store.get_key(fingerprint, private=False)
                if not public_key:
                    pass  # messagebox popup removed
                    return

                # Try to detect signature format
                if "-----BEGIN PGP SIGNED MESSAGE-----" in input_content:
                    # Clear-signed message - pass the whole thing to verify_signature
                    verified, info = verify_signature(input_content, "", public_key)
                elif "-----BEGIN PGP MESSAGE-----" in input_content:
                    # Encrypted message that's also signed
                    verified, info = verify_signature(input_content, "", public_key)
                else:
                    # Try detached signature - parse message and signature
                    lines = input_content.split('\n')
                    sig_start = None
                    msg_end = None
                    for i, line in enumerate(lines):
                        if "-----BEGIN PGP SIGNATURE-----" in line:
                            sig_start = i
                        if sig_start and "-----END PGP SIGNATURE-----" in line:
                            msg_end = i + 1
                            break

                    if sig_start is not None:
                        message = '\n'.join(lines[:sig_start]).strip()
                        signature = '\n'.join(lines[sig_start:msg_end]).strip()
                        verified, info = verify_signature(message, signature, public_key)
                    else:
                        pass  # messagebox popup removed
                        return

                # Show result
                result_label.pack(fill='x', pady=(10, 5))
                result_text.pack(fill='both', expand=True, pady=(0, 10))

                result_text.config(state='normal')
                result_text.delete('1.0', tk.END)

                if verified:
                    result_text.insert('1.0', "✅ SIGNATURE VERIFIED\n\n")
                    result_text.insert(tk.END, "This message was signed by:\n")
                    result_text.insert(tk.END, f"  Name: {info.get('signer_name', 'Unknown')}\n")
                    result_text.insert(tk.END, f"  Email: {info.get('signer_email', 'Unknown')}\n")
                    result_text.insert(tk.END, f"  Key ID: {info.get('key_id', 'Unknown')}\n")
                    result_text.insert(tk.END, f"  Fingerprint: {info.get('fingerprint', 'Unknown')}\n\n")
                    result_text.insert(tk.END, f"Using key: {selected_key_info['name']} [{fingerprint[-16:]}]\n")
                    pass  # messagebox popup removed
                else:
                    result_text.insert('1.0', "❌ SIGNATURE VERIFICATION FAILED\n\n")
                    result_text.insert(
                        tk.END, f"Verifying with key: {selected_key_info['name']} [{fingerprint[-16:]}]\n\n")

                    if 'error' in info:
                        result_text.insert(tk.END, f"Error: {info['error']}\n\n")

                    result_text.insert(tk.END, "Possible reasons:\n")
                    result_text.insert(
                        tk.END, "  • Wrong public key selected (message was signed with a different key)\n")
                    result_text.insert(tk.END, "  • Message was modified after signing\n")
                    result_text.insert(tk.END, "  • Signature format is incorrect\n\n")

                    # Show debug info
                    result_text.insert(tk.END, "--- Debug Info ---\n")
                    for key, value in info.items():
                        if key != 'error':
                            result_text.insert(tk.END, f"{key}: {value}\n")

                result_text.config(state='disabled')

            except Exception as exc:
                self.report_error("Failed to verify signature", exc)
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=10)

        ttk.Button(button_frame, text="Verify", command=verify).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Close", command=dialog.destroy).pack(side='left', padx=5)

    def show_about_dialog(self):
        """Show about dialog with project information."""
        dialog = tk.Toplevel(self.root)
        dialog.title("About Hassle Free PGP")
        dialog.geometry("550x400")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(False, False)

        # Main frame
        main_frame = ttk.Frame(dialog, padding="30")
        main_frame.pack(fill='both', expand=True)

        # Title
        title_label = ttk.Label(main_frame,
                                text="Hassle Free PGP",
                                font=('Arial', 20, 'bold'))
        title_label.pack(pady=(0, 10))

        # Version or tagline
        version_label = ttk.Label(main_frame,
                                  text="Offline PGP Encryption Made Simple",
                                  font=('Arial', 11, 'italic'))
        version_label.pack(pady=(0, 20))

        # Creator info
        creator_frame = ttk.Frame(main_frame)
        creator_frame.pack(pady=(0, 20))

        creator_text = (
            "A passion project by Pierce Alworth\n"
            "@palwoth on GitHub\n\n"
            "This tool was created to make solid encryption tools\n"
            "more accessible and easier to use for everyone.\n\n"
            "No network connections. No telemetry. No nonsense.\n"
            "Just secure, offline PGP encryption."
        )

        creator_label = ttk.Label(creator_frame,
                                  text=creator_text,
                                  font=('Arial', 11),
                                  justify='center')
        creator_label.pack()

        # Links section
        links_frame = ttk.Frame(main_frame)
        links_frame.pack(pady=(10, 20))

        github_label = ttk.Label(links_frame,
                                 text="GitHub: github.com/palwoth",
                                 font=('Arial', 10))
        github_label.pack()

        # Close button
        ttk.Button(main_frame,
                   text="Close",
                   command=dialog.destroy,
                   width=15).pack(pady=(10, 0))

    def clear_action_buttons(self):
        """Clear action buttons frame."""
        for widget in self.action_frame.winfo_children():
            widget.destroy()
        # Delete back_button attribute so it gets recreated next time
        if hasattr(self, 'back_button'):
            del self.back_button


def main():
    """Main entry point."""
    # Set macOS app name (only works on macOS with PyObjC)
    try:
        from Foundation import NSBundle

        # Get the bundle and update its info dictionary
        bundle = NSBundle.mainBundle()
        if bundle:
            info = bundle.localizedInfoDictionary() or bundle.infoDictionary()
            if info and hasattr(info, '__setitem__'):
                info['CFBundleName'] = 'Hassle Free PGP'
                info['CFBundleDisplayName'] = 'Hassle Free PGP'

        # Also set the process name
        try:
            from Foundation import NSProcessInfo
            processInfo = NSProcessInfo.processInfo()
            processInfo.setProcessName_('Hassle Free PGP')
        except BaseException:
            pass

    except ImportError:
        pass  # PyObjC not available

    root = tk.Tk()

    # Additional macOS integration
    try:
        root.createcommand('tk::mac::ShowPreferences', lambda: None)
    except BaseException:
        pass

    PGPApplication(root)
    root.mainloop()


if __name__ == "__main__":
    main()
