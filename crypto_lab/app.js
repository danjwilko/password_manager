
async function deriveKey(password, salt) {
  const enc = new TextEncoder();

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encrypt() {
  const password = document.getElementById("masterPassword").value;
  const text = document.getElementById("plaintext").value;

  const enc = new TextEncoder();

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const key = await deriveKey(password, salt);

  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    key,
    enc.encode(text)
  );

const result = {
  salt: toBase64(salt),
  iv: toBase64(iv),
  data: toBase64(new Uint8Array(ciphertext)),
};

  document.getElementById("output").textContent =
    JSON.stringify(result, null, 2);
}

async function decrypt() {
  const password = document.getElementById("masterPassword").value;
  const output = JSON.parse(document.getElementById("output").textContent);

  const salt = new Uint8Array(output.salt);
  const iv = new Uint8Array(output.iv);
  const data = new Uint8Array(output.data);

  const key = await deriveKey(password, salt);

  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv },
    key,
    data
  );

  const dec = new TextDecoder();

  document.getElementById("output").textContent =
    dec.decode(decrypted);
}

function toBase64(bytes) {
  return btoa(String.fromCharCode(...bytes));
}

function fromBase64(base64) {
  return new Uint8Array(
    atob(base64).split('').map(c => c.charCodeAt(0))
  );
}