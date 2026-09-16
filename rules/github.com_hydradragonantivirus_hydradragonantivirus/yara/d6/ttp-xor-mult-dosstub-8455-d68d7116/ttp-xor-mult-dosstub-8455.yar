rule TTP_XOR_MULT_DOSStub_8455 {
  strings:
    $key_8455 = { d0 3d [2] a4 25 [2] e3 27 [2] a4 36 [2] ea 3a [2] e6 30 [2] f1 3b [2] ea 75 [2] d7 }

  condition:
    any of them
}