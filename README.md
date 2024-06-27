# The Wallet for Nine Chronicles

This is a crypto wallet service of chrome extension for Nine Chronicles blockchain, designed to provide users with a seamless experience in managing their assets on the Nine Chronicles blockchain.

## Stability Notice

This project is intended for development and experimental use, so users are advised to be cautious when using this extension and to back up their private keys regularly.

## Chrono SDK

The project provides the Chrono SDK to interact with the Nine Chronicles blockchain. For more information on the SDK, visit the [Chrono SDK Document](https://jsr.io/@planetarium/chrono-sdk/doc).

## Project Structure

- [`/background`](./background): Implements the background service worker of the chrome extension. This is where important data storage and operations are executed.
- [`/popup`](./popup): Implements the popup UI for the chrome extension. It is responsible for receiving user actions and communicating with the background context.
- [`/packages/chrono-sdk`](./packages/chrono-sdk/): Implements the `jsr:@planetarium/chrono-sdk` package which provides `ChronoWallet` class to communicate with background context, and several hooks to use the `ChronoWallet` as React hooks easily.
- [`/extension`](./extension): Handles the manifest settings.
- [`/examples`](./examples): Contains example applications and use cases demonstrating how to use the wallet in various scenarios.

## Getting Started

### 1. Clone the Project

```sh
git clone https://github.com/planetarium/chrono
cd chrono
pnpm install
```

### 2. Build the Project

```sh
pnpm build
```

### 3. Import Chrome Extension for Development

- Open `chrome://extensions` in Chrome.
- Enable Developer Mode.
- Click on "Load unpacked" and select the `~/chrono/build` directory.

## License

This project is licensed under the GPL-3.0 license.
