rule TTP_XOR_MULT_DOSStub_dac7 {
  strings:
    $key_dac7 = { 8e af [2] fa b7 [2] bd b5 [2] fa a4 [2] b4 a8 [2] b8 a2 [2] af a9 [2] b4 e7 [2] 89 }

  condition:
    any of them
}