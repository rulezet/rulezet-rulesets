rule TTP_XOR_MULT_DOSStub_d532 {
  strings:
    $key_d532 = { 81 5a [2] f5 42 [2] b2 40 [2] f5 51 [2] bb 5d [2] b7 57 [2] a0 5c [2] bb 12 [2] 86 }

  condition:
    any of them
}