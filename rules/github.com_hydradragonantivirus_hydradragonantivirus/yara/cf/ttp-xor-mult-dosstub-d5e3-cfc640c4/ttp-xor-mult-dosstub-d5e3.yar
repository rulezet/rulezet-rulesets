rule TTP_XOR_MULT_DOSStub_d5e3 {
  strings:
    $key_d5e3 = { 81 8b [2] f5 93 [2] b2 91 [2] f5 80 [2] bb 8c [2] b7 86 [2] a0 8d [2] bb c3 [2] 86 }

  condition:
    any of them
}