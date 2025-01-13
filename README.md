# 📜 ttp
[![License: MIT](https://img.shields.io/badge/License-Unlicense-8af7ff.svg)](https://opensource.org/licenses/Unlicense)

Tiny TLS Proxy (TTP) is a lightweight TLS proxy server with authentication support, written in C with just 816 lines of code. It is designed to be extremely resource-efficient and minimalistic.

## Why Another TLS Proxy?
To put it simply: because Stunnel was too bloated for my needs!

To elaborate: I wanted to run a TLS proxy server on my Mikrotik router, which has very limited free memory (~45MB), for a small application I developed. After several attempts to build Stunnel statically using Musl, I observed the following:

- **Storage**: A statically built Stunnel, even with Musl, consumes about ~2.4MB of storage.
- **Memory Usage**: It uses approximately ~2.9MB of RAM.

Given that my Mikrotik has limited storage (~776kB), I needed to run everything in a ramdisk. While ~6MB might seem negligible, I didn't want to waste my precious RAM on such overhead. Additionally, I wanted a solution where the entire configuration could be managed through environment variables, a feature that Stunnel (as far as I know) does not support.

> [!NOTE]
> In Stunnel's defense: I have used and appreciated it for many years. However, it only supports OpenSSL, a library notorious for its size and complexity. Since Stunnel has no plans to support other SSL/TLS libraries, I had no interest in patching it either ;-).

## How?
With OpenSSL out of the question, I decided to try my luck with BearSSL. This library is compact, fully featured, avoids dynamic memory allocations, and can even run on microcontrollers. As a bonus, it is MIT-licensed.

Without further ado, when statically built for ARMv6, TTP occupies just 262kB of storage and uses only ~480kB of RAM. This makes it small enough to fit even on the modest flash memory of my router.

## Usage

Since TTP is entirely configured through environment variables, the table below lists all available variables and their descriptions:

| Variable               | Description                                                                 | Required |
|------------------------|-----------------------------------------------------------------------------|----------|
| `TTP_LISTEN_PORT`      | The port on which the TTP server will listen for incoming connections.      | Yes      |
| `TTP_TARGET_PORT`      | The port of the target server to which TTP will forward the traffic.        | Yes      |
| `TTP_TARGET_HOST`      | IP address of the target server.                                            | Yes      |
| `TTP_LOG_PATH`         | The file path where TTP will write its logs.                                | Yes      |
| `TTP_SERVER_CERT_B64`  | Base64-encoded server certificate (e.g., `fullchain.pem`).                  | Yes      |
| `TTP_SERVER_KEY_B64`   | Base64-encoded private key for the server certificate (e.g., `privkey.pem`).| Yes      |
| `TTP_CA_CERT_B64`      | Base64-encoded CA certificate (e.g., `ca.crt`). Optional for some setups.   | No       |
| `TTP_CHACHA_ONLY`      | When set to `1`, the server will only offer the ChaCha20 cipher suite.      | No       |

### Optional: `TTP_CHACHA_ONLY`
The `TTP_CHACHA_ONLY` variable is optional. When set, the TTP server will exclusively offer the **ChaCha20 cipher suite**. This can be particularly useful for low-end devices, such as a first-generation Raspberry Pi or similar hardware, where performance is limited and lightweight encryption is preferred. By enabling this option, you ensure that the server uses a modern, efficient cipher that is well-suited for resource-constrained environments.

### Optional: `TTP_CA_CERT_B64`
The `TTP_CA_CERT_B64` variable is optional and is used to enable **client certificate authentication**. If you want to verify client certificates, you can provide the base64-encoded CA certificate here. If this variable is omitted, client authentication will not be required.

### Example Configuration
Here’s an example of how to configure TTP using environment variables:

```bash
export TTP_LISTEN_PORT=7171
export TTP_TARGET_PORT=80
export TTP_TARGET_HOST=localhost
export TTP_LOG_PATH=log.txt
export TTP_SERVER_CERT_B64="$(base64 fullchain.pem)"
export TTP_SERVER_KEY_B64="$(base64 privkey.pem)"
export TTP_CA_CERT_B64="$(base64 ca.crt)"  # Optional
export TTP_CHACHA_ONLY=1                   # Optional, for low-end devices
```

This configuration sets up TTP to listen on port `7171`, forward traffic to `localhost:80`, log to `log.txt`, and use the provided certificates. The optional `TTP_CHACHA_ONLY` flag ensures that only the ChaCha20 cipher suite is used, optimizing performance for low-end hardware.

## Build Instructions
The easiest and recommended way to use TTP is via the Docker image available at: [theldus/ttp:latest](https://hub.docker.com/repository/docker/theldus/ttp/tags), compatible with armv6, armv7, and aarch64. However, if you prefer to build it manually, the process is quite straightforward:
```bash
# Clone
$ git clone https://github.com/Theldus/ttp.git
$ cd ttp/

# Build
$ make
```

## Security Notice
Running a Docker image can be a cause for concern, and it is not advisable to blindly trust readily available Docker images. With this in mind, all Docker images provided in this repository are exclusively pushed to Dockerhub via Github Actions. This means you can audit the entire process from start to finish, ensuring that the downloaded Docker images are exactly as they claim to be.

## Contributing
TTP is always open to the community and willing to accept contributions, whether with issues, documentation, testing, new features, bugfixes, typos, and etc. Welcome aboard.

## License
TTP is released into the public domain under the Unlicense license. However, it incorporates code from BearSSL's `tools` (MIT licensed) and `base64.c` (BSD licensed).
