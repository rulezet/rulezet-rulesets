rule TTP_XOR_MULT_DOSStub_8b44 {
  strings:
    $key_8b44 = { df 2c [2] ab 34 [2] ec 36 [2] ab 27 [2] e5 2b [2] e9 21 [2] fe 2a [2] e5 64 [2] d8 }

  condition:
    any of them
}