rule TTP_XOR_MULT_DOSStub_8477 {
  strings:
    $key_8477 = { d0 1f [2] a4 07 [2] e3 05 [2] a4 14 [2] ea 18 [2] e6 12 [2] f1 19 [2] ea 57 [2] d7 }

  condition:
    any of them
}