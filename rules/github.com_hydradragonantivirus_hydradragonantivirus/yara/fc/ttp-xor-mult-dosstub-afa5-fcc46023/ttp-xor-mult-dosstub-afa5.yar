rule TTP_XOR_MULT_DOSStub_afa5 {
  strings:
    $key_afa5 = { fb cd [2] 8f d5 [2] c8 d7 [2] 8f c6 [2] c1 ca [2] cd c0 [2] da cb [2] c1 85 [2] fc }

  condition:
    any of them
}