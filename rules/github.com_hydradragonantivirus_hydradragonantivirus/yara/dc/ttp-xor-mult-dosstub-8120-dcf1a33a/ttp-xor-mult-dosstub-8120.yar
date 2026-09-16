rule TTP_XOR_MULT_DOSStub_8120 {
  strings:
    $key_8120 = { d5 48 [2] a1 50 [2] e6 52 [2] a1 43 [2] ef 4f [2] e3 45 [2] f4 4e [2] ef 00 [2] d2 }

  condition:
    any of them
}