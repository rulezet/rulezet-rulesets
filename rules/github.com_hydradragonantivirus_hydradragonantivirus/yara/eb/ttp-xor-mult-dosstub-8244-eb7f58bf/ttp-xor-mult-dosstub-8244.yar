rule TTP_XOR_MULT_DOSStub_8244 {
  strings:
    $key_8244 = { d6 2c [2] a2 34 [2] e5 36 [2] a2 27 [2] ec 2b [2] e0 21 [2] f7 2a [2] ec 64 [2] d1 }

  condition:
    any of them
}