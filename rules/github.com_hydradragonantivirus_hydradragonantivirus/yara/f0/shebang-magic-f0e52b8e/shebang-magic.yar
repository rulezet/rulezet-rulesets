rule shebang_magic {
  condition:
    uint16(0) == 0x2123
}