rule head_mz_d_med_100kb_1mb {
  condition:
    uint16be(0) == 0x4d5a
    and filesize > 100KB and filesize < 1000KB
}