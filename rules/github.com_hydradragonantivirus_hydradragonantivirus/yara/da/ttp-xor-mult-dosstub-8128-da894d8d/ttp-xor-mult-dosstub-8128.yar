rule TTP_XOR_MULT_DOSStub_8128 {
  strings:
    $key_8128 = { d5 40 [2] a1 58 [2] e6 5a [2] a1 4b [2] ef 47 [2] e3 4d [2] f4 46 [2] ef 08 [2] d2 }

  condition:
    any of them
}