# How to Run

This is tested on Ubuntu only.
The system to which the devices are connected will be known as PRIMARY. The system to share it with is called SECONDARY.

Be careful when adding these permissions - these give permissions for reading inputs to a third-party server.
Note that the data of input devices is shared across the local network the systems are connected to, but it is still advised to be careful of what you're doing when installing or executing something new.

1. On BOTH systems, run the following:
```
sudo apt install -y python3-evdev openssl openssh-server
sudo install -m 755 sharies.py /usr/local/bin/sharies
sudo groupadd -r sharies
sudo usermod -aG sharies $USER
echo 'KERNEL=="uinput", SUBSYSTEM=="misc", GROUP="sharies", MODE="0660", OPTIONS+="static_node=uinput"' | sudo tee /etc/udev/rules.d/99-sharies-uinput.rules
echo uinput | sudo tee /etc/modules-load.d/sharies.conf
```

2. On PRIMARY system, run: `sudo usermod -aG input $USER`

3. Restart both systems

4. On BOTH systems, generate keys: `sharies genkey`

5. Get username and hostname information by running this on the SECONDARY system:
```
whoami
hostname
```

6. Replace the values for `USER` and `HOST` and execute the following commands to copy over the generated keys:
```
scp ~/.config/sharies/cert.pem USER@HOST.local:~/.config/sharies/peer.pem
scp USER@HOST.local:~/.config/sharies/cert.pem ~/.config/sharies/peer.pem
```

7. Check fingerprints on BOTH the systems: `sharies fingerprint`

8. Start the receiver by running this on SECONDARY: `sharies receive`

9. Start the PRIMARY: `sharies share <HOST>.local`

10. Press `Ctrl + Shift + /` to switch between systems. To stop, come back to Primary, click its terminal and press Ctrl+C.
