rule TTP_XOR_MULT_DOSStub_af40 {
  strings:
    $key_af40 = { fb 28 [2] 8f 30 [2] c8 32 [2] 8f 23 [2] c1 2f [2] cd 25 [2] da 2e [2] c1 60 [2] fc }

  condition:
    any of them
}