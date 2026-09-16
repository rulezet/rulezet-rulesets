rule TTP_XOR_MULT_DOSStub_d536 {
  strings:
    $key_d536 = { 81 5e [2] f5 46 [2] b2 44 [2] f5 55 [2] bb 59 [2] b7 53 [2] a0 58 [2] bb 16 [2] 86 }

  condition:
    any of them
}