rule TTP_XOR_MULT_DOSStub_89c3 {
  strings:
    $key_89c3 = { dd ab [2] a9 b3 [2] ee b1 [2] a9 a0 [2] e7 ac [2] eb a6 [2] fc ad [2] e7 e3 [2] da }

  condition:
    any of them
}