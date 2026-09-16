rule IcedIDSyscallWriteMem
{
    meta:
        author = "kevoreilly"
        description = "IcedID 'syscall' packer bypass - direct write variant"
        cape_options = "bp0=$tokencheck+9,action0=jmp,count=0"
        packed = "28075ecae5e224c06e250f2c949c826b81844bca421e9158a7a9e965a29ef894"
        packed = "045dff9f14a03225df55997cb2ca74ff60ecaf317b9e033ea93386785db84161"
    strings:
        $tokencheck = {39 5D ?? 75 06 83 7D ?? 03 74 05 BB 01 00 00 00 41 89 1C ?? 48 8B 4D ?? 41 FF D?}
    condition:
        uint16(0) == 0x5A4D and all of them
}