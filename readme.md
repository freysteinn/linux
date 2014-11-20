# LightNVM: A host-side driver for Open-Channel Solid State Drives

Open-channel SSDs are devices which exposes direct access to its physical flash
storage, while keeping a subset of the internal features of SSDs.

LightNVM moves part of the internal SSD flash translation layer into the host,
allowing it to manage data placement, garbage collection and parallelism. The
device continus to maintain information about bad blocks, and implements a simpler
flash translation layer, that allows extensions, such as atomic IOs metadata
persistence and similar.

The architecture of LightNVM consists of a core and multiple targets. The core
has the parts of the driver that is shared across targets, initialization and
teardown and statistics. The targets defines how physical flash are exposed to
user-land. This can be as a block-device, key-value store, object-store, or
anything else.

LightNVM is currently hooked up through the null_blk and NVMe driver. The NVMe
extension allows development using the LightNVM-extended QEMU implementation.

# How to run 

Follow the how to at https://github.com/OpenChannelSSD/linux/wiki
