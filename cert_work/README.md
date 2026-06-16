# TLS Development Certificate

The HTTPS server needs an X.509 certificate and its matching private key.
A self-signed **development** certificate is embedded directly in
[`port/app/mbedtls/src/SSLInterface.c`](../port/app/mbedtls/src/SSLInterface.c)
(`HTTPS_SERVER_CERT[]` / `HTTPS_SERVER_KEY[]`).

> ⚠️ The bundled certificate is for **demo/testing only**. It is self-signed,
> so browsers will show a security warning (expected). Generate your own before
> any real use. Private keys are git-ignored in this folder and are **never**
> committed.

## Regenerate a self-signed cert + key

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout server.key.pem -out server.cert.pem \
    -subj "/C=KR/O=WIZnet Demo/OU=HTTPS Test/CN=W55RP20-Demo" \
    -addext "subjectAltName=IP:192.168.11.118,DNS:w55rp20.local"
```

Replace the IP/DNS in `subjectAltName` with your device's address.

## Embed into the firmware

Convert each PEM file into a C string array and paste it over the
`HTTPS_SERVER_CERT[]` / `HTTPS_SERVER_KEY[]` definitions in `SSLInterface.c`.
Each line becomes `    "<line>\r\n"`, the last line ends with `\r\n";`.

PowerShell helper:

```powershell
function ToCArray($name, $pem) {
  $lines = (Get-Content $pem) | Where-Object { $_ -ne '' }
  "static const char $name" + "[] ="
  for ($i = 0; $i -lt $lines.Count; $i++) {
    $term = if ($i -eq $lines.Count - 1) { '\r\n";' } else { '\r\n"' }
    '    "' + $lines[$i] + $term
  }
}
ToCArray HTTPS_SERVER_CERT server.cert.pem
ToCArray HTTPS_SERVER_KEY  server.key.pem
```

bash helper:

```bash
to_c_array() {  # $1 = array name, $2 = pem file
  echo "static const char $1[] ="
  sed '/^$/d' "$2" | sed 's/.*/    "&\\r\\n"/; $s/"$/";/'
}
to_c_array HTTPS_SERVER_CERT server.cert.pem
to_c_array HTTPS_SERVER_KEY  server.key.pem
```
