rule TTP_XOR_MULT_DOSStub_8108 {
  strings:
    $key_8108 = { d5 60 [2] a1 78 [2] e6 7a [2] a1 6b [2] ef 67 [2] e3 6d [2] f4 66 [2] ef 28 [2] d2 }

  condition:
    any of them
}