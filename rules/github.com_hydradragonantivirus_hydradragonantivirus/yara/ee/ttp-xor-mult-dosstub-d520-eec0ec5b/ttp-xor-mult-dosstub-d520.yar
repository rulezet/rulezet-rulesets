rule TTP_XOR_MULT_DOSStub_d520 {
  strings:
    $key_d520 = { 81 48 [2] f5 50 [2] b2 52 [2] f5 43 [2] bb 4f [2] b7 45 [2] a0 4e [2] bb 00 [2] 86 }

  condition:
    any of them
}