rule TTP_XOR_MULT_DOSStub_af27 {
  strings:
    $key_af27 = { fb 4f [2] 8f 57 [2] c8 55 [2] 8f 44 [2] c1 48 [2] cd 42 [2] da 49 [2] c1 07 [2] fc }

  condition:
    any of them
}