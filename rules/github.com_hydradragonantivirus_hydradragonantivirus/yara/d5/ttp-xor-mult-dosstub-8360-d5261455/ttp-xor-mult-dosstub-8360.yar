rule TTP_XOR_MULT_DOSStub_8360 {
  strings:
    $key_8360 = { d7 08 [2] a3 10 [2] e4 12 [2] a3 03 [2] ed 0f [2] e1 05 [2] f6 0e [2] ed 40 [2] d0 }

  condition:
    any of them
}