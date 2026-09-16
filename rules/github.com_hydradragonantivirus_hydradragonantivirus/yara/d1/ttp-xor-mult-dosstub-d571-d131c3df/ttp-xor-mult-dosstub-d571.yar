rule TTP_XOR_MULT_DOSStub_d571 {
  strings:
    $key_d571 = { 81 19 [2] f5 01 [2] b2 03 [2] f5 12 [2] bb 1e [2] b7 14 [2] a0 1f [2] bb 51 [2] 86 }

  condition:
    any of them
}