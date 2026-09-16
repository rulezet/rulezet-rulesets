rule TTP_XOR_MULT_DOSStub_8132 {
  strings:
    $key_8132 = { d5 5a [2] a1 42 [2] e6 40 [2] a1 51 [2] ef 5d [2] e3 57 [2] f4 5c [2] ef 12 [2] d2 }

  condition:
    any of them
}