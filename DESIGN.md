# EASY PGP - BRUTALIST DESIGN

## Design Philosophy

Easy PGP now features a **brutalist/minimalist** design inspired by modernist web templates. The interface is stripped down to its essential elements with a bold, utilitarian aesthetic.

## Color Scheme

### Primary Colors
- **Black** (`#000000`) - Main background
- **White** (`#FFFFFF`) - Primary text and borders
- **Dark Grey** (`#1a1a1a`) - Panel backgrounds
- **Very Dark Grey** (`#0a0a0a`) - Input fields

### Accent Colors
- **Medium Grey** (`#333333`) - Interactive elements (hover states)
- **Light Grey** (`#CCCCCC`) - Secondary text

## Typography

- **Font**: Courier New (monospace)
- **Style**: Bold, uppercase for all labels and buttons
- **Sizes**:
  - Headers: 12-18pt
  - Body text: 10pt
  - Status bar: 9pt

## Design Elements

### 1. Window
- Title: **"EASY PGP"** (uppercase)
- Size: 1000x750px
- Background: Pure black

### 2. Menu Bar
- Black background with white text
- Uppercase labels: "KEYS", "OPERATIONS"
- Bold Courier New font
- 2px solid borders

### 3. Main Interface

#### Left Panel - Keyring
- Black treeview with white text
- 2px white borders
- Monospace font
- Selected items: dark grey background

#### Right Panel - Work Area
- **Welcome State**: 
  - Centered text: "SELECT AN OPERATION FROM THE MENU"
  - Light grey color
  - Large, bold typography
  
- **Active State**:
  - Mode label with brackets: `[ SIGN MESSAGE ]`
  - Input/Output frames with uppercase labels
  - Black text areas with white text
  - Bold 2px borders

### 4. Buttons
- Black background
- White text with brackets: `[ SIGN ]`, `[ ENCRYPT ]`
- 2px solid white borders
- Dark grey on hover
- Sunken effect on press
- Uppercase, bold text

### 5. Status Bar
- Dark grey background
- White text
- Bracketed format: `[ READY ]`, `[ LOADED 2 KEY(S) ]`
- Fixed to bottom
- 2px top border

## Key Features

### Minimalism
- No rounded corners
- No gradients
- No shadows
- Flat colors only
- Sharp, geometric shapes

### High Contrast
- Pure black and white
- No mid-tones except for interactive states
- Maximum legibility

### Functionality First
- Form follows function
- No decorative elements
- Every pixel serves a purpose
- Clear visual hierarchy

### Typography-Driven
- Heavy use of uppercase
- Monospace font throughout
- Bold weights for emphasis
- Bracket notation for status/actions

## Inspiration

The design draws from:
- Brutalist web design movement
- Swiss/International Typographic Style
- Terminal/command-line interfaces
- Modernist architecture
- 1960s-70s institutional design

## User Experience

### Clarity
- High contrast ensures readability
- Monospace fonts provide alignment
- Uppercase draws attention to important actions

### Focus
- Minimal distractions
- Clean workspace
- Hidden elements until needed

### Confidence
- Bold, assertive interface
- Clear feedback through status bar
- Bracketed text emphasizes system state

## Technical Implementation

### Tkinter Styling
- Custom `ttk.Style()` configuration
- Override default themes
- Manual color specification for all widgets
- Font consistency across application

### Widget Configuration
```python
colors = {
    'bg': '#000000',           # Black background
    'fg': '#FFFFFF',           # White text
    'panel_bg': '#1a1a1a',     # Dark grey panels
    'border': '#FFFFFF',       # White borders
    'button_bg': '#000000',    # Black buttons
    'button_fg': '#FFFFFF',    # White button text
    'button_active': '#333333', # Grey on hover
    'input_bg': '#0a0a0a',     # Very dark grey for inputs
    'accent': '#CCCCCC',       # Light grey accent
    'status_bg': '#1a1a1a',    # Status bar background
}
```

## Future Enhancements

Potential additions while maintaining the aesthetic:
- ASCII art logo
- Animated bracket loader: `[ /// ]`
- Keyboard-only navigation
- Command palette
- Grid-based layouts
- More terminal-inspired elements

