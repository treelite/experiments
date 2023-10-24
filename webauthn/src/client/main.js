const getIdentityId = () => {
  const input = document.getElementById("ipt-identity-id");
  return input.value.trim();
};

const getChallenge = async () => {
  const res = await fetch("/challenge");
  if (!res.ok) {
    throw new Error(`failed to fech challenge: ${res.status}`);
  }

  return await res.arrayBuffer();
};

const SPLITER = "\n".charCodeAt(0);

const mergeUint8Array = (buffers, spliter = SPLITER)  => {
  buffers = buffers.map((buffer) => {
    if (buffer instanceof Uint8Array) {
      return buffer;
    }
    if (buffer instanceof ArrayBuffer) {
      return new Uint8Array(buffer);
    }
    return Uint8Array.from(buffer);
  });
  const bufferCount = buffers.length;
  const len = buffers.reduce((res, buffer) => res += buffer.length, 0) + buffers.length - 1;

  const res = new Uint8Array(len);
  let i = 0;
  buffers.forEach((buffer, j) => {
    res.set(buffer, i);
    i += buffer.length;
    if (j + 1 < bufferCount) {
      res.set([spliter], i++);
    }
  });
  return res;
};

const encodeText = (text) => {
  const encoder = new TextEncoder();
  return encoder.encode(text);
};

const saveCredential = async (name, credential) => {
  const id = credential.rawId;
  const clientData = credential.response.clientDataJSON;
  const publicKey = credential.response.getPublicKey();
  const payload = mergeUint8Array([name, id, clientData, publicKey]);

  const res = await fetch("/credential", { method: "put", body: payload });

  if (!res.ok) {
    throw new Error(`failed to save credential: ${res.status}`);
  }
};

const register = async (name) => {
  const nameBuffer = encodeText(name);
  const challenge = await getChallenge();
  const publicKeyOptions = {
    challenge,
    rp: {
      name: "WebAuthn Test",
      id: "localhost",
    },
    user: {
      id: nameBuffer,
      name,
      displayName: name,
    },
    // Prefer ES256
    // https://www.iana.org/assignments/cose/cose.xhtml#algorithms
    pubKeyCredParams: [{alg: -7, type: "public-key"}],
    timeout: 60000,
  };

  const credential = await navigator.credentials.create({ publicKey: publicKeyOptions });

  return saveCredential(nameBuffer, credential);
};

const getCredentialId = async (name) => {
  const res = await fetch(`/credential-id?name=${encodeURIComponent(name)}`);
  if (!res.ok) {
    throw new Error(`failed to get credential id: ${res.status}`);
  }

  return res.arrayBuffer();
};

const verify = async (name) => {
  const [challenge, credentialId] = await Promise.all([getChallenge(), getCredentialId(name)]);

  const credential = await navigator.credentials.get({
    publicKey: {
      challenge,
      allowCredentials: [{
        id: credentialId,
        type: "public-key",
      }],
      timeout: 60000,
    },
  });

  const { signature, authenticatorData, clientDataJSON } = credential.response;
  const payload = mergeUint8Array([credential.rawId, signature, authenticatorData, clientDataJSON]);

  const res = await fetch("/authorize", { body: payload, method: "POST" });
  if (!res.ok) {
    throw new Error(`failed to authorize: ${res.status}`);
  }
};

document.getElementById("btn-register").addEventListener("click", async () => {
  const id = getIdentityId();
  if (!id) {
    alert("Please type your name first");
    return;
  }

  await register(id);
  alert("Registration success");
});

document.getElementById("btn-authorize").addEventListener("click", async () => {
  const id = getIdentityId();
  if (!id) {
    alert("Please type your name first");
    return;
  }

  await verify(id);
  alert("Authorization success");
});
