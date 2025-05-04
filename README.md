# OCSP Response Reader Tool

📜 A lightweight Java tool to decode and display human-readable details from a Base64-encoded OCSP (Online Certificate Status Protocol) response.

---

## 🔧 Description

The **OCSPRespReader** parses an OCSP response provided as a Base64-encoded string (without PEM headers), and prints out data:

- ✅ Certificate serial number  
- 🔒 Certificate status 
- ⏰ Revocation time (if revoked)  
- 📅 ThisUpdate

## 🚀 Usage

### Arguments:

- `<path_to_file>` – A Base64-encoded OCSP response string **without** PEM headers (`-----BEGIN OCSP RESPONSE-----` / `-----END OCSP RESPONSE-----`)

## 💡 Example
java -jar OCSPRespReader-1.0.jar <path-to-file>

## 🛠 Output
INFO: The Certificate with CertID: 75D6470C6F17EFD1 is GOOD
Last Update: Mon May 30 08:52:57 CEST 2016

## 📦 Dependencies

- Java 21
- [Bouncy Castle](https://www.bouncycastle.org/java.html) (for OCSP parsing)


## 🧪 Testing

Unit tests are included using **JUnit 4**. To run:

```bash
./gradlew test
