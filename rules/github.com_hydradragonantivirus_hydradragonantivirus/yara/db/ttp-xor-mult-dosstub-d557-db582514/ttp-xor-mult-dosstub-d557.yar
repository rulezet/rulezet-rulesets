rule TTP_XOR_MULT_DOSStub_d557 {
  strings:
    $key_d557 = { 81 3f [2] f5 27 [2] b2 25 [2] f5 34 [2] bb 38 [2] b7 32 [2] a0 39 [2] bb 77 [2] 86 }

  condition:
    any of them
}