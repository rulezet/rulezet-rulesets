rule PE {
  meta:
    description = "private rule to match PE binaries"

  condition:
    uint16(0) == 0x5a4d and uint32(uint32(0x3C)) == 0x4550
}