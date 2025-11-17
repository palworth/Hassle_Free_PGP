# Hassle Free PGP - User Guide for Everyone

## 📥 How to Install (Super Easy!)

### Step 1: Download
Download the file: `Hassle_Free_PGP.zip`

### Step 2: Unzip
Double-click the ZIP file. It will create an app called **"Hassle Free PGP"**

### Step 3: Move to Applications
Drag the app to your **Applications** folder (optional but recommended)

### Step 4: Open
Double-click the app to open it!

### ⚠️ First Time Only: "Can't be opened" error?
If you see a security warning:
1. **Right-click** (or Control-click) on the app
2. Click **"Open"**
3. Click **"Open"** again in the popup

You only have to do this once! After that, just double-click normally.

---

## 🎯 What This App Does

**Hassle Free PGP** lets you send secret messages that only specific people can read.

Think of it like a super-secure lockbox:
- You can **lock** a message so only your friend can unlock it
- You can **unlock** messages that were locked for you
- You can **sign** messages to prove they're really from you
- You can **verify** that messages are really from who they say

---

## 🔑 First Time Setup: Create Your Keys

When you first open the app:

1. Click **KEYS** menu → **CREATE NEW KEY**
2. Enter a **label** for your key (like "My Main Key" or your name)
3. Choose a **password** (you'll need this to read messages!)
4. Click **Generate PGP Keys**
5. Wait a minute while it creates your keys...
6. Done! You now have:
   - A **PUBLIC KEY** - Share this with people who want to send you messages
   - A **PRIVATE KEY** - NEVER share this! Keep it secret!

---

## 📤 How to Send a Secret Message

1. Get the other person's **PUBLIC KEY** (they can email/text it to you)
2. Click **OPERATIONS** → **ENCRYPT**
3. Type your message in the top box
4. Paste their public key in the middle box
5. Click **Encrypt**
6. Copy the encrypted message at the bottom
7. Send it to them (email, text, carrier pigeon - doesn't matter! It's encrypted!)

**What they receive:** Gibberish that only they can decrypt!

---

## 📥 How to Read a Secret Message Someone Sent You

1. Click **OPERATIONS** → **DECRYPT**
2. Select your key from the dropdown
3. Enter your password
4. Paste the encrypted message
5. Click **Decrypt a Message**
6. Read the secret message!

---

## ✍️ How to Sign a Message (Prove It's From You)

1. Click **OPERATIONS** → **SIGN**
2. Type your message
3. Click your key in the keyring
4. Click **[ SIGN ]**
5. Enter your password
6. Copy the signed message
7. Send it!

**What this does:** Adds a digital signature that proves YOU wrote it and it hasn't been changed.

---

## ✅ How to Verify a Signed Message

1. Click **OPERATIONS** → **VERIFY**
2. Select the sender's key from dropdown
3. Paste their signed message
4. Click **Verify**

If it says **"✅ SIGNATURE VERIFIED"** → It's legit!  
If it says **"❌ VERIFICATION FAILED"** → Something's wrong!

---

## 🔑 Managing Your Keys

### View Your Keys
Look at the **KEY-RING** on the left side. All your keys are listed there.

### Import Someone's Public Key
1. Get their public key (they'll send it to you)
2. Click **KEYS** → **IMPORT KEY**
3. Click the **"Import Public Key"** tab
4. Paste their key
5. Give it a name (like "Alice" or "Bob")
6. Click **Import Public Key**

### Share Your Public Key
1. Right-click your key in the keyring
2. Click **Export Key** → **Export Public Key**
3. Copy it and send it to people

**Remember:** Public keys are meant to be shared! Private keys are NOT!

---

## 🤔 Common Questions

### "Do I need internet to use this?"
**Nope!** This works 100% offline. No data is sent anywhere.

### "Where are my keys stored?"
On your computer only, in a secure database. They never leave your Mac.

### "Can the government/FBI/anyone read my messages?"
If you follow the steps correctly: **NO**. PGP encryption is mathematically secure. Even supercomputers can't crack it (with current technology).

### "What if I forget my password?"
Unfortunately, there's no recovery. That's the price of true security. **Write down your password somewhere safe!**

### "Can I use this to email people?"
Yes! But you'll need to copy/paste the encrypted messages into your email. This app doesn't send emails directly (by design - no internet = no tracking).

### "Is this really secure?"
Yes! This uses the same PGP encryption used by journalists, whistleblowers, and security professionals worldwide. The code is open source so anyone can verify it.

---

## 🆘 Troubleshooting

### App won't open
- Make sure you're on macOS 10.13 or newer
- Try the right-click → Open trick (see installation section above)
- Try running this in Terminal:
  ```
  xattr -cr "/Applications/Hassle Free PGP.app"
  ```

### "Key not found" error
Make sure you've imported the person's key first (KEYS → IMPORT KEY)

### Decryption fails
- Check your password (it's case-sensitive!)
- Make sure the encrypted message was encrypted TO your key
- Make sure you have the full encrypted message (including the BEGIN/END markers)

### Generated keys aren't showing up
Click **KEYS** → **REFRESH KEYRING**

---

## 💡 Pro Tips

1. **Backup your keys!** Right-click → Export and save them somewhere safe
2. **Use a password manager** to store your key passwords
3. **Verify signatures** on important messages to prevent fraud
4. **Test it first** by sending encrypted messages to yourself
5. **Keep your private key secret** - treat it like your bank password!

---

## 📚 Want to Learn More?

The app has more information at the bottom of the main screen. Read it to understand why PGP matters for privacy and freedom online.

---

## ❤️ Support

This is a free, open-source project by Pierce Alworth (@palwoth on GitHub).

No tracking. No telemetry. No corporate BS. Just solid encryption tools for everyone.

If you find this useful, share it with friends who value privacy!

---

**You're all set! Stay safe and keep your communications private. 🔐**

