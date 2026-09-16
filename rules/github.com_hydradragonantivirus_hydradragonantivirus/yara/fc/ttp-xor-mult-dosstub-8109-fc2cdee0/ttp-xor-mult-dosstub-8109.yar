rule TTP_XOR_MULT_DOSStub_8109 {
  strings:
    $key_8109 = { d5 61 [2] a1 79 [2] e6 7b [2] a1 6a [2] ef 66 [2] e3 6c [2] f4 67 [2] ef 29 [2] d2 }

  condition:
    any of them
}