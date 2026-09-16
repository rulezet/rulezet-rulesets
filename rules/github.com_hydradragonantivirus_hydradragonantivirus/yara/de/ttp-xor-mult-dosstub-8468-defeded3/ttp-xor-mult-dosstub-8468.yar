rule TTP_XOR_MULT_DOSStub_8468 {
  strings:
    $key_8468 = { d0 00 [2] a4 18 [2] e3 1a [2] a4 0b [2] ea 07 [2] e6 0d [2] f1 06 [2] ea 48 [2] d7 }

  condition:
    any of them
}