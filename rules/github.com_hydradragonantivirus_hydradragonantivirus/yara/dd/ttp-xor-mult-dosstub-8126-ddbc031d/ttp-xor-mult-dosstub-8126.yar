rule TTP_XOR_MULT_DOSStub_8126 {
  strings:
    $key_8126 = { d5 4e [2] a1 56 [2] e6 54 [2] a1 45 [2] ef 49 [2] e3 43 [2] f4 48 [2] ef 06 [2] d2 }

  condition:
    any of them
}