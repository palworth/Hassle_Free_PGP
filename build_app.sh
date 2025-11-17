#!/bin/bash
# Build script for creating the Mac .app bundle
# This creates a standalone app that users can just double-click

set -e  # Exit on any error

echo "======================================"
echo "Building Hassle Free PGP.app"
echo "======================================"
echo ""

# Check if virtual environment is active
if [ -z "$VIRTUAL_ENV" ]; then
    echo "⚠️  Virtual environment not active. Activating..."
    source venv/bin/activate
fi

# Install py2app if not already installed
echo "📦 Installing py2app (if needed)..."
pip install py2app pyobjc-framework-Cocoa pyobjc-core --quiet

# Clean previous builds
echo "🧹 Cleaning previous builds..."
rm -rf build dist

# Build the app
echo "🔨 Building standalone .app (this may take a few minutes)..."
python setup.py py2app

# Check if build was successful
if [ -d "dist/Hassle Free PGP.app" ]; then
    echo ""
    echo "✅ SUCCESS!"
    echo ""
    echo "======================================"
    echo "Your app is ready!"
    echo "======================================"
    echo ""
    echo "📂 Location: dist/Hassle Free PGP.app"
    echo ""
    echo "To test it:"
    echo "  open 'dist/Hassle Free PGP.app'"
    echo ""
    echo "To distribute:"
    echo "  1. Zip the app: cd dist && zip -r 'Hassle_Free_PGP.zip' 'Hassle Free PGP.app'"
    echo "  2. Share the zip file with users"
    echo "  3. Users just unzip and drag to Applications folder"
    echo ""
    echo "App size: $(du -sh "dist/Hassle Free PGP.app" | cut -f1)"
    echo ""
else
    echo ""
    echo "❌ Build failed. Check the output above for errors."
    exit 1
fi

