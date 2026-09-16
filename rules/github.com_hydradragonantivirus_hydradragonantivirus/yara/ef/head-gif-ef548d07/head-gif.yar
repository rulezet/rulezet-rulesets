rule head_gif {
  condition:
    uint32be(0) == 0x47494638
}