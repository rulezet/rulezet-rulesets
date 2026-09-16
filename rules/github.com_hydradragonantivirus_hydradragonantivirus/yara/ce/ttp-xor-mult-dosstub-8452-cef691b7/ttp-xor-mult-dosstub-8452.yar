rule TTP_XOR_MULT_DOSStub_8452 {
  strings:
    $key_8452 = { d0 3a [2] a4 22 [2] e3 20 [2] a4 31 [2] ea 3d [2] e6 37 [2] f1 3c [2] ea 72 [2] d7 }

  condition:
    any of them
}