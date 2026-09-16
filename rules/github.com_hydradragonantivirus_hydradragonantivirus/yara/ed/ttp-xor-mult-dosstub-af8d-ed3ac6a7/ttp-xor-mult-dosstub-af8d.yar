rule TTP_XOR_MULT_DOSStub_af8d {
  strings:
    $key_af8d = { fb e5 [2] 8f fd [2] c8 ff [2] 8f ee [2] c1 e2 [2] cd e8 [2] da e3 [2] c1 ad [2] fc }

  condition:
    any of them
}