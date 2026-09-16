rule TTP_XOR_MULT_DOSStub_d5e1 {
  strings:
    $key_d5e1 = { 81 89 [2] f5 91 [2] b2 93 [2] f5 82 [2] bb 8e [2] b7 84 [2] a0 8f [2] bb c1 [2] 86 }

  condition:
    any of them
}