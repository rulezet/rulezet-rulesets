rule TTP_XOR_MULT_DOSStub_8344 {
  strings:
    $key_8344 = { d7 2c [2] a3 34 [2] e4 36 [2] a3 27 [2] ed 2b [2] e1 21 [2] f6 2a [2] ed 64 [2] d0 }

  condition:
    any of them
}