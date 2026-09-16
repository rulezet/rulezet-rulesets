rule TTP_XOR_MULT_DOSStub_8150 {
  strings:
    $key_8150 = { d5 38 [2] a1 20 [2] e6 22 [2] a1 33 [2] ef 3f [2] e3 35 [2] f4 3e [2] ef 70 [2] d2 }

  condition:
    any of them
}