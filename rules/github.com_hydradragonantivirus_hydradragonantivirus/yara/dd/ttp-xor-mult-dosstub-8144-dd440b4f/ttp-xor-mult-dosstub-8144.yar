rule TTP_XOR_MULT_DOSStub_8144 {
  strings:
    $key_8144 = { d5 2c [2] a1 34 [2] e6 36 [2] a1 27 [2] ef 2b [2] e3 21 [2] f4 2a [2] ef 64 [2] d2 }

  condition:
    any of them
}