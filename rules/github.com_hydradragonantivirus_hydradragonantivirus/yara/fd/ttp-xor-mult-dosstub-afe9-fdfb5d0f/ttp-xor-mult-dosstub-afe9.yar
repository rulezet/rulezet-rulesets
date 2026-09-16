rule TTP_XOR_MULT_DOSStub_afe9 {
  strings:
    $key_afe9 = { fb 81 [2] 8f 99 [2] c8 9b [2] 8f 8a [2] c1 86 [2] cd 8c [2] da 87 [2] c1 c9 [2] fc }

  condition:
    any of them
}