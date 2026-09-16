rule TTP_XOR_MULT_DOSStub_8472 {
  strings:
    $key_8472 = { d0 1a [2] a4 02 [2] e3 00 [2] a4 11 [2] ea 1d [2] e6 17 [2] f1 1c [2] ea 52 [2] d7 }

  condition:
    any of them
}