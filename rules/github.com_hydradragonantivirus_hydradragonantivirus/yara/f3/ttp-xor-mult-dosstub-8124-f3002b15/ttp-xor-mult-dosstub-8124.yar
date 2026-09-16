rule TTP_XOR_MULT_DOSStub_8124 {
  strings:
    $key_8124 = { d5 4c [2] a1 54 [2] e6 56 [2] a1 47 [2] ef 4b [2] e3 41 [2] f4 4a [2] ef 04 [2] d2 }

  condition:
    any of them
}