rule TTP_XOR_MULT_DOSStub_afb8 {
  strings:
    $key_afb8 = { fb d0 [2] 8f c8 [2] c8 ca [2] 8f db [2] c1 d7 [2] cd dd [2] da d6 [2] c1 98 [2] fc }

  condition:
    any of them
}