rule TTP_XOR_MULT_DOSStub_dac3 {
  strings:
    $key_dac3 = { 8e ab [2] fa b3 [2] bd b1 [2] fa a0 [2] b4 ac [2] b8 a6 [2] af ad [2] b4 e3 [2] 89 }

  condition:
    any of them
}