# sharies

Use one keyboard and mouse on two Ubuntu machines. Press **Ctrl + Shift + /** to switch between them.

Tested on Ubuntu 24.04 only.

- **PRIMARY**: the machine the keyboard and mouse are connected to.
- **SECONDARY**: the machine you want to control from it.

Both machines must run the same version of `sharies.py`.

## Security

- Input travels only from PRIMARY to SECONDARY over your local network. It is encrypted, and each machine accepts only the other's certificate. No other server is involved.
- **The `input` group (PRIMARY only)** lets any program you run read every keystroke.
- **The `sharies` group** lets any program you run create virtual input devices that type on that machine.
- **`~/.config/sharies/key.pem`** is the private key. Anyone who gets PRIMARY's key can type on SECONDARY. Never copy or share it.

## Setup

### 1. Install (on BOTH machines)

Run these from the folder that contains `sharies.py`:

```bash
sudo apt install -y python3-evdev openssl
sudo install -m 755 sharies.py /usr/local/bin/sharies
sudo groupadd -r sharies          # "already exists" is fine
sudo usermod -aG sharies $USER
echo 'KERNEL=="uinput", SUBSYSTEM=="misc", GROUP="sharies", MODE="0660", OPTIONS+="static_node=uinput"' | sudo tee /etc/udev/rules.d/99-sharies-uinput.rules
echo uinput | sudo tee /etc/modules-load.d/sharies.conf
```

### 2. Extra permissions

On **PRIMARY** only:

```bash
sudo usermod -aG input $USER
```

On **SECONDARY** only (needed to receive the certificate in step 6):

```bash
sudo apt install -y openssh-server
```

### 3. Restart both machines

This applies the new groups and the device rule.

### 4. Generate certificates (on BOTH machines)

```bash
sharies genkey
```

### 5. Find SECONDARY's username and hostname (on SECONDARY)

```bash
whoami
hostname
```

### 6. Exchange certificates (on PRIMARY)

Replace `USER` and `HOST` with the values from step 5:

```bash
scp ~/.config/sharies/cert.pem USER@HOST.local:~/.config/sharies/peer.pem
scp USER@HOST.local:~/.config/sharies/cert.pem ~/.config/sharies/peer.pem
```

This copies only the certificates (`cert.pem`). Never copy `key.pem`.

If `HOST.local` is not found, use SECONDARY's IP address instead. On SECONDARY, run:

```bash
ip -4 route get 1.1.1.1 | grep -o 'src [0-9.]*'
```

### 7. Check fingerprints (on BOTH machines)

```bash
sharies fingerprint
```

Each machine's "this machine" line must match the other machine's "peer" line. If they don't match, repeat step 6.

### 8. Optional: firewall (on SECONDARY)

Allow only PRIMARY to connect. Find PRIMARY's IP with the same `ip` command as in step 6:

```bash
sudo ufw allow from PRIMARY_IP to any port 24850 proto tcp
```

## Use

1. On **SECONDARY**: `sharies receive`
2. On **PRIMARY**: `sharies share HOST.local` (or SECONDARY's IP address)
3. Press **Ctrl + Shift + /** to switch between the machines.

To stop, switch back to PRIMARY, click its terminal and press **Ctrl+C**. If sharies ever stops or crashes, your keyboard and mouse go straight back to normal.

To see which devices will be shared, run `sharies list` on PRIMARY.

## Troubleshooting

| Message | Fix |
|---|---|
| `no read/write access to /dev/uinput` | Steps 1–3 didn't apply. Check `ls -l /dev/uinput` (group should be `sharies`) and `groups`, then restart. |
| `cannot open any input device` | On PRIMARY, your user isn't in the `input` group yet. Restart after step 2. |
| `cannot connect to ...` | Make sure `sharies receive` is running on SECONDARY. Check the address and the firewall rule. |
| `... cannot be used` (at startup) | Run `sharies genkey --force` on the machine named in the message, then repeat steps 6–7. |
| `the receiver refused the session` | Check SECONDARY's window for the reason, and compare fingerprints (step 7). |
| `runs a different ... version` | Install the same `sharies.py` on both machines. |
