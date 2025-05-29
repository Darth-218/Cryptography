const cryptoService = {
    baseUrl: 'http://localhost:5000',

    async rsaEncrypt(message) {
        const response = await fetch(`${this.baseUrl}/rsa/encrypt`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'RSA encryption failed');
        }

        return response.json();
    },

    async rsaDecrypt(encrypted, n, d) {
        const response = await fetch(`${this.baseUrl}/rsa/decrypt`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ encrypted, n, d })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'RSA decryption failed');
        }

        return response.json();
    },

    async hmacSign(message, key) {
        const response = await fetch(`${this.baseUrl}/hmac/sign`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message, key })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'HMAC signing failed');
        }

        return response.json();
    },

    async aesEncrypt(message, key) {
        const response = await fetch(`${this.baseUrl}/aes/encrypt`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message, key })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'AES encryption failed');
        }

        return response.json();
    },

    async aesDecrypt(encrypted, key) {
        const response = await fetch(`${this.baseUrl}/aes/decrypt`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ encrypted, key })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'AES decryption failed');
        }

        return response.json();
    }
};

const elements = {
    rsaCheckbox: document.getElementById('rsaCheckbox'),
    hmacCheckbox: document.getElementById('hmacCheckbox'),
    aesCheckbox: document.getElementById('aesCheckbox'),

    rsaResult: document.getElementById('rsaResult'),
    hmacResult: document.getElementById('hmacResult'),
    aesResult: document.getElementById('aesResult'),

    errorMessage: document.getElementById('errorMessage'),

    startButton: document.getElementById('startButton'),

    hmacKeyInput: document.getElementById('hmacKey'),
    aesKeyInput: document.getElementById('aesKey'),

    hmacKeyContainer: document.getElementById('hmacKeyContainer'),
    aesKeyContainer: document.getElementById('aesKeyContainer'),
    rsaKeyContainer: document.getElementById('rsaKeyContainer'),

    rsaEncryptFields: document.getElementById('rsaEncryptFields'),
    rsaDecryptFields: document.getElementById('rsaDecryptFields'),

    encryptRadio: document.getElementById('encrypt'),
    decryptRadio: document.getElementById('decrypt'),

    rsaModulus: document.getElementById('rsaModulus'),
    rsaPrivate: document.getElementById('rsaPrivate'),

    input: document.querySelector('.text-input'),

    rsaKeyDisplay: document.getElementById('rsaKeyDisplay'),
    hmacKeyDisplay: document.getElementById('hmacKeyDisplay'),
    aesKeyDisplay: document.getElementById('aesKeyDisplay'),

    rsaKeyText: document.getElementById('rsaKeyText'),
    hmacKeyText: document.getElementById('hmacKeyText'),
    aesKeyText: document.getElementById('aesKeyText'),
};

const validation = {
    showError(message) {
        elements.errorMessage.textContent = message;
        elements.errorMessage.style.display = 'block';
    },

    hideError() {
        elements.errorMessage.style.display = 'none';
    },

    validateInput() {
        const inputText = elements.input.value.trim();

        if (!elements.rsaCheckbox.checked && !elements.hmacCheckbox.checked && !elements.aesCheckbox.checked) {
            throw new Error('Please select at least one algorithm!');
        }

        if (!inputText) {
            throw new Error('Please enter some text to process!');
        }

        if (elements.hmacCheckbox.checked && !elements.hmacKeyInput.value.trim()) {
            throw new Error('Please enter an HMAC key!');
        }

        if (elements.aesCheckbox.checked && !elements.aesKeyInput.value.trim()) {
            throw new Error('Please enter an AES key!');
        }

        return inputText;
    },

    validateRsaDecryption(inputText) {
        const hexInput = inputText.replace(/\s+/g, '');
        const modulus = elements.rsaModulus.value.trim();
        const privateKey = elements.rsaPrivate.value.trim();

        if (!hexInput || !modulus || !privateKey) {
            throw new Error('Please enter the encrypted message (in hex format), modulus (n), and private key (d)!');
        }

        if (!/^[0-9A-Fa-f]+$/.test(hexInput)) {
            throw new Error('For RSA decryption, the input must be in hexadecimal format (e.g., "1A2B3C")');
        }

        if (!/^\d+$/.test(modulus) || !/^\d+$/.test(privateKey)) {
            throw new Error('The modulus (n) and private key (d) must be valid positive integers');
        }

        if (BigInt(modulus) <= BigInt(0) || BigInt(privateKey) <= BigInt(0)) {
            throw new Error('The modulus (n) and private key (d) must be positive numbers');
        }

        return { hexInput, modulus, privateKey };
    }
};

const ui = {
    updateVisibility() {
        const isEncrypt = elements.encryptRadio.checked;
        
        const hmacOption = document.querySelector('[for="hmacCheckbox"]').parentElement;
        hmacOption.style.display = isEncrypt ? 'block' : 'none';
        if (!isEncrypt) {
            elements.hmacCheckbox.checked = false;
        }

        elements.rsaResult.style.display = elements.rsaCheckbox.checked ? 'block' : 'none';
        elements.rsaKeyDisplay.style.display = elements.rsaCheckbox.checked ? 'block' : 'none';

        elements.hmacResult.style.display = elements.hmacCheckbox.checked ? 'block' : 'none';
        elements.hmacKeyDisplay.style.display = elements.hmacCheckbox.checked ? 'block' : 'none';

        elements.aesResult.style.display = elements.aesCheckbox.checked ? 'block' : 'none';
        elements.aesKeyDisplay.style.display = elements.aesCheckbox.checked ? 'block' : 'none';

        elements.hmacKeyContainer.style.display = elements.hmacCheckbox.checked ? 'block' : 'none';
        elements.aesKeyContainer.style.display = elements.aesCheckbox.checked ? 'block' : 'none';
        elements.rsaKeyContainer.style.display = elements.rsaCheckbox.checked ? 'block' : 'none';

        if (elements.rsaCheckbox.checked) {
            elements.rsaEncryptFields.style.display = isEncrypt ? 'block' : 'none';
            elements.rsaDecryptFields.style.display = isEncrypt ? 'none' : 'block';
        }

        validation.hideError();
    },

    clearResults() {
        elements.rsaResult.value = '';
        elements.hmacResult.value = '';
        elements.aesResult.value = '';
    },

    displayRsaResult(data, modulus = '', privateKey = '') {
        elements.rsaResult.value = data.encrypted || data.decrypted;
        if (data.encrypted) {
            elements.rsaKeyText.textContent = `Public key (n, e): ${data.n}, ${data.e}\nPrivate key (d): ${data.d}`;
        } else {
            elements.rsaKeyText.textContent = `Used keys:\n  n: ${modulus}\n  d: ${privateKey}`;
        }
        elements.rsaKeyDisplay.style.display = 'block';
    },

    displayHmacResult(hmac, key) {
        elements.hmacResult.value = hmac;
        elements.hmacKeyText.textContent = `Key: ${key}`;
        elements.hmacKeyDisplay.style.display = 'block';
    },

    displayAesResult(data, key) {
        elements.aesResult.value = data.encrypted || data.decrypted;
        elements.aesKeyText.textContent = `Key: ${key}`;
        elements.aesKeyDisplay.style.display = 'block';
    }
};

// Event handlers
async function handleRsa(inputText, isEncrypt) {
    if (isEncrypt) {
        const data = await cryptoService.rsaEncrypt(inputText);
        ui.displayRsaResult(data);
    } else {
        const { hexInput, modulus, privateKey } = validation.validateRsaDecryption(inputText);
        const data = await cryptoService.rsaDecrypt(hexInput, modulus, privateKey);
        ui.displayRsaResult(data, modulus, privateKey);
    }
}

async function handleHmac(inputText) {
    const key = elements.hmacKeyInput.value;
    const data = await cryptoService.hmacSign(inputText, key);
    ui.displayHmacResult(data.hmac, key);
}

async function handleAes(inputText, isEncrypt) {
    const key = elements.aesKeyInput.value;
    const data = isEncrypt 
        ? await cryptoService.aesEncrypt(inputText, key)
        : await cryptoService.aesDecrypt(inputText, key);
    ui.displayAesResult(data, key);
}

async function handleCryptoOperation(event) {
    event.preventDefault();
    
    try {
        validation.hideError();
        ui.clearResults();

        const inputText = validation.validateInput();
        const isEncrypt = elements.encryptRadio.checked;

        if (elements.rsaCheckbox.checked) {
            await handleRsa(inputText, isEncrypt);
        }
        
        if (elements.hmacCheckbox.checked) {
            await handleHmac(inputText);
        }
        
        if (elements.aesCheckbox.checked) {
            await handleAes(inputText, isEncrypt);
        }
    } catch (error) {
        validation.showError(error.message);
    }
}

ui.updateVisibility();

elements.rsaCheckbox.addEventListener('change', ui.updateVisibility);
elements.hmacCheckbox.addEventListener('change', ui.updateVisibility);
elements.aesCheckbox.addEventListener('change', ui.updateVisibility);

elements.encryptRadio.addEventListener('change', ui.updateVisibility);
elements.decryptRadio.addEventListener('change', ui.updateVisibility);
elements.startButton.addEventListener('click', handleCryptoOperation);
