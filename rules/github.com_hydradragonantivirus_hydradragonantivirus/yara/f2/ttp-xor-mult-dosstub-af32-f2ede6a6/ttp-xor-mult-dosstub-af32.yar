rule TTP_XOR_MULT_DOSStub_af32 {
  strings:
    $key_af32 = { fb 5a [2] 8f 42 [2] c8 40 [2] 8f 51 [2] c1 5d [2] cd 57 [2] da 5c [2] c1 12 [2] fc }

  condition:
    any of them
}