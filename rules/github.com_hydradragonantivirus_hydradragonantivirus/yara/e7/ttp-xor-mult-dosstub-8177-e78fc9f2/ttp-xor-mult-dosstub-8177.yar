rule TTP_XOR_MULT_DOSStub_8177 {
  strings:
    $key_8177 = { d5 1f [2] a1 07 [2] e6 05 [2] a1 14 [2] ef 18 [2] e3 12 [2] f4 19 [2] ef 57 [2] d2 }

  condition:
    any of them
}