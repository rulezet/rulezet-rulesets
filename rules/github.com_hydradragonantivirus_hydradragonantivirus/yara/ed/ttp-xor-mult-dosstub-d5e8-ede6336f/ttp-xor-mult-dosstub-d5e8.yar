rule TTP_XOR_MULT_DOSStub_d5e8 {
  strings:
    $key_d5e8 = { 81 80 [2] f5 98 [2] b2 9a [2] f5 8b [2] bb 87 [2] b7 8d [2] a0 86 [2] bb c8 [2] 86 }

  condition:
    any of them
}