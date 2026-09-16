rule TTP_XOR_MULT_DOSStub_8110 {
  strings:
    $key_8110 = { d5 78 [2] a1 60 [2] e6 62 [2] a1 73 [2] ef 7f [2] e3 75 [2] f4 7e [2] ef 30 [2] d2 }

  condition:
    any of them
}