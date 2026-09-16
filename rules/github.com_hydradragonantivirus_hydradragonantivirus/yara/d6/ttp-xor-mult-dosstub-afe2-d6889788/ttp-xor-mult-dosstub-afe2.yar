rule TTP_XOR_MULT_DOSStub_afe2 {
  strings:
    $key_afe2 = { fb 8a [2] 8f 92 [2] c8 90 [2] 8f 81 [2] c1 8d [2] cd 87 [2] da 8c [2] c1 c2 [2] fc }

  condition:
    any of them
}