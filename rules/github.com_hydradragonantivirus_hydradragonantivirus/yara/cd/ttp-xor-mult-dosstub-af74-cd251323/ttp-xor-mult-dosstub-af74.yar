rule TTP_XOR_MULT_DOSStub_af74 {
  strings:
    $key_af74 = { fb 1c [2] 8f 04 [2] c8 06 [2] 8f 17 [2] c1 1b [2] cd 11 [2] da 1a [2] c1 54 [2] fc }

  condition:
    any of them
}