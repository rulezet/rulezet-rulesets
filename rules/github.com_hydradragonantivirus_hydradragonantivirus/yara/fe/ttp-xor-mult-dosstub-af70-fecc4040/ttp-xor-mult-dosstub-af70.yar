rule TTP_XOR_MULT_DOSStub_af70 {
  strings:
    $key_af70 = { fb 18 [2] 8f 00 [2] c8 02 [2] 8f 13 [2] c1 1f [2] cd 15 [2] da 1e [2] c1 50 [2] fc }

  condition:
    any of them
}