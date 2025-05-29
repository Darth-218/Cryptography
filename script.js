const rsaCheckbox = document.getElementById('rsaCheckbox');
const hmacCheckbox = document.getElementById('hmacCheckbox');
const aesCheckbox = document.getElementById('aesCheckbox');
const rsaResult = document.getElementById('rsaResult');
const hmacResult = document.getElementById('hmacResult');
const aesResult = document.getElementById('aesResult');
const errorMessage = document.getElementById('errorMessage');
const startButton = document.getElementById('startButton');
const hmacKeyInput = document.getElementById('hmacKey');
const aesKeyInput = document.getElementById('aesKey');
const hmacKeyContainer = document.getElementById('hmacKeyContainer');
const aesKeyContainer = document.getElementById('aesKeyContainer');
const rsaKeyContainer = document.getElementById('rsaKeyContainer');
const rsaEncryptFields = document.getElementById('rsaEncryptFields');
const rsaDecryptFields = document.getElementById('rsaDecryptFields');
const encryptRadio = document.getElementById('encrypt');
const decryptRadio = document.getElementById('decrypt');
const rsaModulus = document.getElementById('rsaModulus');
const rsaPrivate = document.getElementById('rsaPrivate');

// Key display elements
const rsaKeyDisplay = document.getElementById('rsaKeyDisplay');
const hmacKeyDisplay = document.getElementById('hmacKeyDisplay');
const aesKeyDisplay = document.getElementById('aesKeyDisplay');
const rsaKeyText = document.getElementById('rsaKeyText');
const hmacKeyText = document.getElementById('hmacKeyText');
const aesKeyText = document.getElementById('aesKeyText');

function updateVisibility() {
  const isEncrypt = encryptRadio.checked;

  // Hide HMAC option completely in decrypt mode
  const hmacOption = document.querySelector('[for="hmacCheckbox"]').parentElement;
  hmacOption.style.display = isEncrypt ? 'block' : 'none';
  if (!isEncrypt) {
    hmacCheckbox.checked = false;
  }

  rsaResult.style.display = rsaCheckbox.checked ? 'block' : 'none';
  rsaKeyDisplay.style.display = rsaCheckbox.checked ? 'block' : 'none';
  hmacResult.style.display = hmacCheckbox.checked ? 'block' : 'none';
  hmacKeyDisplay.style.display = hmacCheckbox.checked ? 'block' : 'none';
  aesResult.style.display = aesCheckbox.checked ? 'block' : 'none';
  aesKeyDisplay.style.display = aesCheckbox.checked ? 'block' : 'none';

  hmacKeyContainer.style.display = hmacCheckbox.checked ? 'block' : 'none';
  aesKeyContainer.style.display = aesCheckbox.checked ? 'block' : 'none';
  rsaKeyContainer.style.display = rsaCheckbox.checked ? 'block' : 'none';

  if (rsaCheckbox.checked) {
    rsaEncryptFields.style.display = isEncrypt ? 'block' : 'none';
    rsaDecryptFields.style.display = isEncrypt ? 'none' : 'block';
  }

  errorMessage.style.display = 'none';
}

// Add event listeners
updateVisibility();
rsaCheckbox.addEventListener('change', updateVisibility);
hmacCheckbox.addEventListener('change', updateVisibility);
aesCheckbox.addEventListener('change', updateVisibility);
encryptRadio.addEventListener('change', updateVisibility);
decryptRadio.addEventListener('change', updateVisibility);

startButton.addEventListener('click', async function () {
  const inputText = document.querySelector('.text-input').value.trim();
  const isEncrypt = encryptRadio.checked;
  const operation = isEncrypt ? 'Encrypting' : 'Decrypting';

  // Reset previous results and errors
  errorMessage.style.display = 'none';
  rsaResult.value = '';
  hmacResult.value = '';
  aesResult.value = '';

  if (!rsaCheckbox.checked && !hmacCheckbox.checked && !aesCheckbox.checked) {
    errorMessage.textContent = 'Please select at least one algorithm!';
    errorMessage.style.display = 'block';
    return;
  }

  if (!inputText) {
    errorMessage.textContent = 'Please enter some text to process!';
    errorMessage.style.display = 'block';
    return;
  }

  if (hmacCheckbox.checked && !hmacKeyInput.value.trim()) {
    errorMessage.textContent = 'Please enter an HMAC key!';
    errorMessage.style.display = 'block';
    return;
  }

  if (aesCheckbox.checked && !aesKeyInput.value.trim()) {
    errorMessage.textContent = 'Please enter an AES key!';
    errorMessage.style.display = 'block';
    return;
  }

  if (rsaCheckbox.checked && !isEncrypt) {
    // Additional validation for RSA decryption
    const hexInput = inputText.replace(/\s+/g, '');  // Remove all whitespace
    const modulus = rsaModulus.value.trim();
    const privateKey = rsaPrivate.value.trim();

    if (!hexInput || !modulus || !privateKey) {
      errorMessage.textContent = 'Please enter the encrypted message (in hex format), modulus (n), and private key (d)!';
      errorMessage.style.display = 'block';
      return;
    }

    // Validate hex format for RSA decryption
    if (!/^[0-9A-Fa-f]+$/.test(hexInput)) {
      errorMessage.textContent = 'For RSA decryption, the input must be in hexadecimal format (e.g., "1A2B3C")';
      errorMessage.style.display = 'block';
      return;
    }

    // Basic key format validation
    if (!/^\d+$/.test(modulus) || !/^\d+$/.test(privateKey)) {
      errorMessage.textContent = 'The modulus (n) and private key (d) must be valid positive integers';
      errorMessage.style.display = 'block';
      return;
    }

    // Additional key validation
    if (BigInt(modulus) <= BigInt(0) || BigInt(privateKey) <= BigInt(0)) {
      errorMessage.textContent = 'The modulus (n) and private key (d) must be positive numbers';
      errorMessage.style.display = 'block';
      return;
    }

    try {
      const response = await fetch('http://localhost:5000/rsa/decrypt', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          encrypted: hexInput,
          n: modulus,
          d: privateKey
        })
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Decryption failed');
      }

      const data = await response.json();
      if (data.error) {
        throw new Error(data.error);
      }

      rsaResult.value = `${data.decrypted}`;
      rsaKeyText.textContent = `Used keys:\n  n: ${modulus}\n  d: ${privateKey}`;
      rsaKeyDisplay.style.display = 'block';

    } catch (error) {
      errorMessage.textContent = `Decryption failed: ${error.message}`;
      errorMessage.style.display = 'block';
      return;
    }
  } else if (rsaCheckbox.checked) {
    // RSA encryption
    try {
      const response = await fetch('http://localhost:5000/rsa/encrypt', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          message: inputText
        })
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Encryption failed');
      }

      const data = await response.json();
      if (data.error) {
        throw new Error(data.error);
      }

      rsaKeyText.textContent = 
        `Public key (n, e): ${data.n}, ${data.e}\n` +
        `Private key (d): ${data.d}`;
      rsaResult.value = data.encrypted;
      rsaKeyDisplay.style.display = 'block';

    } catch (error) {
      errorMessage.textContent = `Encryption failed: ${error.message}`;
      errorMessage.style.display = 'block';
      return;
    }
  }

  try {
    if (hmacCheckbox.checked) {
      const key = hmacKeyInput.value;
      const response = await fetch('http://localhost:5000/hmac/sign', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          message: inputText,
          key: key
        })
      });
      const data = await response.json();
      hmacResult.value = data.hmac;
      hmacKeyText.textContent = `Key: ${key}`;
      hmacKeyDisplay.style.display = 'block';
    }

    if (aesCheckbox.checked) {
      const key = aesKeyInput.value;
      const endpoint = isEncrypt ? '/aes/encrypt' : '/aes/decrypt';
      const body = isEncrypt ? 
        { message: inputText, key: key } : 
        { encrypted: inputText, key: key };

      const response = await fetch(`http://localhost:5000${endpoint}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body)
      });

      const data = await response.json();
      if (data.error) {
        throw new Error(data.error);
      }

      aesResult.value = isEncrypt ? data.encrypted : data.decrypted;
      aesKeyText.textContent = `Key: ${key}`;
      aesKeyDisplay.style.display = 'block';
    }
  } catch (error) {
    errorMessage.textContent = 'Error connecting to the server. Make sure the server is running.';
    errorMessage.style.display = 'block';
  }
});
