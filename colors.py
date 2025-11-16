"""
Centralized color configuration for Easy PGP.
All colors used throughout the application are defined here.
"""

# Main application colors
COLORS = {
    # Background colors
    'bg': '#F9F6EE',           # Bone white - main background
    'panel_bg': '#F0EDE5',     # Slightly darker bone for panels
    'status_bg': '#F0EDE5',    # Bone white status bar
    
    # Text colors
    'fg': '#000000',           # Black - primary text
    'text_grey': '#666666',    # Medium grey - secondary text
    'text_dark_grey': '#333333', # Dark grey - info section text
    
    # Button colors - ENCRYPT, DECRYPT, SIGN, VERIFY
    'button_fill': '#262626',      # Very dark grey - main operation button fill
    'button_text': '#FFFFFF',      # White - button text color
    'button_border': '#000000',    # Black - button borders
    'button_active': '#262626',    # Same as fill - no color change on click
    
    # Other button colors
    'button_bg': '#000000',        # Black buttons (legacy)
    'button_fg': '#FFFFFF',        # White button text (legacy)
    
    # Input/Interactive elements
    'input_bg': '#CCCCCC',     # Grey for inputs/keyring
    'border': '#000000',       # Black borders
    
    # Operations panel
    'operations_bg': '#F9F6EE', # Bone white - same as bottom section
    
    # Accent colors
    'accent': '#666666',       # Medium grey accent
}

# Specific component colors for easy reference
BUTTON_COLORS = {
    'fill': COLORS['button_fill'],      # #262626 - Very dark grey
    'text': COLORS['button_text'],      # #FFFFFF - White
    'border': COLORS['button_border'],  # #000000 - Black
    'active': COLORS['button_active'],  # #262626 - Same as fill
}

# Info section colors
INFO_COLORS = {
    'header': COLORS['fg'],           # #000000 - Black headers
    'body': COLORS['text_dark_grey'], # #333333 - Dark grey body text
    'bg': COLORS['bg'],               # Bone white background
}

