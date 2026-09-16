rule TTP_XOR_MULT_DOSStub_a563 {
  strings:
    $key_a563 = { f1 0b [2] 85 13 [2] c2 11 [2] 85 00 [2] cb 0c [2] c7 06 [2] d0 0d [2] cb 43 [2] f6 }

  condition:
    any of them
}