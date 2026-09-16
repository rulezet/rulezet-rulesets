rule TTP_XOR_MULT_DOSStub_8159 {
  strings:
    $key_8159 = { d5 31 [2] a1 29 [2] e6 2b [2] a1 3a [2] ef 36 [2] e3 3c [2] f4 37 [2] ef 79 [2] d2 }

  condition:
    any of them
}