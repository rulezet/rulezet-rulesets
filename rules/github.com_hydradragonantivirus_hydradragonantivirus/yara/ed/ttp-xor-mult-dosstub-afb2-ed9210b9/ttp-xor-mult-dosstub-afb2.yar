rule TTP_XOR_MULT_DOSStub_afb2 {
  strings:
    $key_afb2 = { fb da [2] 8f c2 [2] c8 c0 [2] 8f d1 [2] c1 dd [2] cd d7 [2] da dc [2] c1 92 [2] fc }

  condition:
    any of them
}