rule TTP_XOR_MULT_DOSStub_af49 {
  strings:
    $key_af49 = { fb 21 [2] 8f 39 [2] c8 3b [2] 8f 2a [2] c1 26 [2] cd 2c [2] da 27 [2] c1 69 [2] fc }

  condition:
    any of them
}