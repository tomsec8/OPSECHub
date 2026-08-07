// 🔒 Tool: Document Encryptor & Decryptor (AES-256-GCM Offline)
function initDocEncryptorTool() {
    const fileInput = document.getElementById('input-enc-file');
    const passwordInput = document.getElementById('txt-enc-password');
    const showPasswordChk = document.getElementById('chk-show-enc-password');
    const encryptBtn = document.getElementById('btn-encrypt-file');
    const decryptBtn = document.getElementById('btn-decrypt-file');
    const statusEl = document.getElementById('status-enc-tool');

    if (!fileInput || !encryptBtn || !decryptBtn) return;

    // Show/Hide Password
    if (showPasswordChk && passwordInput) {
        showPasswordChk.addEventListener('change', (e) => {
            passwordInput.type = e.target.checked ? 'text' : 'password';
        });
    }

    // Helper: Derive CryptoKey from password string using PBKDF2
    async function getCryptoKey(password, salt, mode) {
        const encoder = new TextEncoder();
        const baseKey = await crypto.subtle.importKey(
            'raw',
            encoder.encode(password),
            'PBKDF2',
            false,
            ['deriveKey']
        );
        return crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 100000,
                hash: 'SHA-256'
            },
            baseKey,
            { name: 'AES-GCM', length: 256 },
            false,
            [mode]
        );
    }

    const processFile = async (mode) => {
        const file = fileInput.files[0];
        const password = passwordInput.value;
        if (!file || !password) {
            statusEl.textContent = '❌ Please select a file and enter a password.';
            statusEl.style.color = '#ff453a';
            return;
        }

        statusEl.textContent = mode === 'encrypt' ? '⏳ Encrypting...' : '⏳ Decrypting...';
        statusEl.style.color = '#00e5ff';

        try {
            const fileBytes = new Uint8Array(await file.arrayBuffer());

            if (mode === 'encrypt') {
                const salt = crypto.getRandomValues(new Uint8Array(16));
                const iv = crypto.getRandomValues(new Uint8Array(12));
                const key = await getCryptoKey(password, salt, 'encrypt');

                const encryptedContent = await crypto.subtle.encrypt(
                    { name: 'AES-GCM', iv: iv },
                    key,
                    fileBytes
                );

                // Package: [16 bytes salt][12 bytes iv][encrypted data]
                const result = new Uint8Array(salt.length + iv.length + encryptedContent.byteLength);
                result.set(salt, 0);
                result.set(iv, salt.length);
                result.set(new Uint8Array(encryptedContent), salt.length + iv.length);

                const blob = new Blob([result], { type: 'application/octet-stream' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = file.name + '.enc';
                a.click();
                URL.revokeObjectURL(url);

                statusEl.textContent = '✅ File Encrypted and Downloaded successfully!';
                statusEl.style.color = '#30d158';
            } else {
                if (fileBytes.length < 28) {
                    throw new Error('File is too short to be a valid encrypted document.');
                }
                const salt = fileBytes.slice(0, 16);
                const iv = fileBytes.slice(16, 28);
                const data = fileBytes.slice(28);

                const key = await getCryptoKey(password, salt, 'decrypt');
                
                let decryptedContent;
                try {
                    decryptedContent = await crypto.subtle.decrypt(
                        { name: 'AES-GCM', iv: iv },
                        key,
                        data
                    );
                } catch (decErr) {
                    throw new Error('Incorrect password or corrupted file contents. Decryption failed.');
                }

                const cleanName = file.name.replace(/\.enc$/i, '');
                const blob = new Blob([decryptedContent], { type: 'application/octet-stream' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = cleanName;
                a.click();
                URL.revokeObjectURL(url);

                statusEl.textContent = '✅ File Decrypted and Downloaded successfully!';
                statusEl.style.color = '#30d158';
            }
        } catch (err) {
            console.error(err);
            statusEl.textContent = '❌ Decryption failed. Verify that your password is valid and matches the encrypted file.';
            statusEl.style.color = '#ff453a';
        }
    };

    encryptBtn.addEventListener('click', () => processFile('encrypt'));
    decryptBtn.addEventListener('click', () => processFile('decrypt'));
}
