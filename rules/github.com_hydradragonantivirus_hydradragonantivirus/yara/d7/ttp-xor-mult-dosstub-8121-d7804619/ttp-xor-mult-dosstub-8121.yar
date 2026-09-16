rule TTP_XOR_MULT_DOSStub_8121 {
  strings:
    $key_8121 = { d5 49 [2] a1 51 [2] e6 53 [2] a1 42 [2] ef 4e [2] e3 44 [2] f4 4f [2] ef 01 [2] d2 }

  condition:
    any of them
}