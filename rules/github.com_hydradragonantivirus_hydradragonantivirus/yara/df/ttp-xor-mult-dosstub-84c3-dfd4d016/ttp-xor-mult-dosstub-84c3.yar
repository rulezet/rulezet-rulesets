rule TTP_XOR_MULT_DOSStub_84c3 {
  strings:
    $key_84c3 = { d0 ab [2] a4 b3 [2] e3 b1 [2] a4 a0 [2] ea ac [2] e6 a6 [2] f1 ad [2] ea e3 [2] d7 }

  condition:
    any of them
}