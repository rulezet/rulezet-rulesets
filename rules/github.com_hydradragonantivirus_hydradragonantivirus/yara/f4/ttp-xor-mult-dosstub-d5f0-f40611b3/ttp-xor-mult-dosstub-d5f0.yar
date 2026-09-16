rule TTP_XOR_MULT_DOSStub_d5f0 {
  strings:
    $key_d5f0 = { 81 98 [2] f5 80 [2] b2 82 [2] f5 93 [2] bb 9f [2] b7 95 [2] a0 9e [2] bb d0 [2] 86 }

  condition:
    any of them
}