## Quickstart

Add this to your Cargo.toml:

```toml
[dependencies]
walletconnect-client = "0.1"
```

And this to your code:

```rust
use walletconnect-client::prelude::*;
```

To initiate walletconnect connection with the wallet, set up your dApps metadata:

```rust
let dapp = Metadata::from("Your dApp's name", "Your dApp's short description", "https://url.of.your.dapp", vec!["https://url.to.your.dapps.icon".to_string()]);
```

...and once you'll get your projects id from WalletConnect portal, you can simply create the connection:

```rust 
let client = WalletConnect::connect(PROJECT_ID, 1 /* Ethereums chain id */, dapp, Some(Box::new(move |event| debug!("Received an event from WallectConnect {event:?}")))).await?;
let url = client.initiate_session().await?;
```

Now your wallet need to get your sessions url. You can pass it on using url call with proper schema, or present it using qrcode like:

```rust 
let png_vec =
qrcode_generator::to_png_to_vec(&url, QrCodeEcc::Low, 512).unwrap();
svg.set(format!(
            "data:image/png;base64,{}",
            data_encoding::BASE64.encode(&png_vec)
            ));
```

## Documentation

In progress of creation.

## Features

- [X] Session creation and handling
- [ ] Handling manual chain changes
- [ ] Handling transaction signatures
- [ ] Handling typed data signatures
- [ ] Handling non-WASM usage for servers

## Note on WASM

This library currently needs WASM to work. There is a plan to support server-side implementations, though. For now, we focus on building robust solution for WASM implementations of websites.
