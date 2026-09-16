rule head_jpeg {
  condition:
    uint32be(0) == 0xffd8ffe0
}