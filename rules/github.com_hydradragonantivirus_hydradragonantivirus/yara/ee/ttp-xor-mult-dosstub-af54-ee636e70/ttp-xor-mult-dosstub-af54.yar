rule TTP_XOR_MULT_DOSStub_af54 {
  strings:
    $key_af54 = { fb 3c [2] 8f 24 [2] c8 26 [2] 8f 37 [2] c1 3b [2] cd 31 [2] da 3a [2] c1 74 [2] fc }

  condition:
    any of them
}