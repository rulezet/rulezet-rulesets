rule TTP_XOR_MULT_DOSStub_8447 {
  strings:
    $key_8447 = { d0 2f [2] a4 37 [2] e3 35 [2] a4 24 [2] ea 28 [2] e6 22 [2] f1 29 [2] ea 67 [2] d7 }

  condition:
    any of them
}