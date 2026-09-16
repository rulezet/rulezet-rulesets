rule TTP_XOR_MULT_DOSStub_8116 {
  strings:
    $key_8116 = { d5 7e [2] a1 66 [2] e6 64 [2] a1 75 [2] ef 79 [2] e3 73 [2] f4 78 [2] ef 36 [2] d2 }

  condition:
    any of them
}