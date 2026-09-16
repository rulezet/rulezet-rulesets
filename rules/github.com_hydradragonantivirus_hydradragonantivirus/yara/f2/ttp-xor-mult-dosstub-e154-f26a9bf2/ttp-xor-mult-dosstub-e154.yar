rule TTP_XOR_MULT_DOSStub_e154 {
  strings:
    $key_e154 = { b5 3c [2] c1 24 [2] 86 26 [2] c1 37 [2] 8f 3b [2] 83 31 [2] 94 3a [2] 8f 74 [2] b2 }

  condition:
    any of them
}