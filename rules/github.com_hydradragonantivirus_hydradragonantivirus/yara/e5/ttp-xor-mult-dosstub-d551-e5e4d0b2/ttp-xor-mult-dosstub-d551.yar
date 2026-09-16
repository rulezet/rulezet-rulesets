rule TTP_XOR_MULT_DOSStub_d551 {
  strings:
    $key_d551 = { 81 39 [2] f5 21 [2] b2 23 [2] f5 32 [2] bb 3e [2] b7 34 [2] a0 3f [2] bb 71 [2] 86 }

  condition:
    any of them
}