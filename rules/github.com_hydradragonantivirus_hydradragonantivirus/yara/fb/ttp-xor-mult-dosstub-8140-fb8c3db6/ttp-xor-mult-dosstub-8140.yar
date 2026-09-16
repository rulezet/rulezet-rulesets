rule TTP_XOR_MULT_DOSStub_8140 {
  strings:
    $key_8140 = { d5 28 [2] a1 30 [2] e6 32 [2] a1 23 [2] ef 2f [2] e3 25 [2] f4 2e [2] ef 60 [2] d2 }

  condition:
    any of them
}