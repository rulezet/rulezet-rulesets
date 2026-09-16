rule TTP_XOR_MULT_DOSStub_d554 {
  strings:
    $key_d554 = { 81 3c [2] f5 24 [2] b2 26 [2] f5 37 [2] bb 3b [2] b7 31 [2] a0 3a [2] bb 74 [2] 86 }

  condition:
    any of them
}