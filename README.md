# Over Ride

This project follows the RainFall project. It will teach you how to exploit the (elf-like) binary.

## Virutal Machine

The project requires virtual machine with special .iso image. Download it on the project page

### Run

```bash
qemu-system-x86_64 -boot d -cdrom OverRide.iso -m 2048 -net nic -net user,hostfwd=tcp::4242-:4242
```

Note that we're allocating 2gb of RAM.