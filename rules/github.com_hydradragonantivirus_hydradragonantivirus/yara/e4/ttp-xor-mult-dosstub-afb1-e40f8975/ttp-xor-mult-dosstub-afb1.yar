rule TTP_XOR_MULT_DOSStub_afb1 {
  strings:
    $key_afb1 = { fb d9 [2] 8f c1 [2] c8 c3 [2] 8f d2 [2] c1 de [2] cd d4 [2] da df [2] c1 91 [2] fc }

  condition:
    any of them
}