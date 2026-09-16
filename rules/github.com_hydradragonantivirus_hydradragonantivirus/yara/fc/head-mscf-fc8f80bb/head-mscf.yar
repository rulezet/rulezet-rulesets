rule head_mscf {
  condition:
    uint32be(0) == 0x4d534346
}