rule head_gz {
  condition:
    uint16be(0) == 0x1f8b
}