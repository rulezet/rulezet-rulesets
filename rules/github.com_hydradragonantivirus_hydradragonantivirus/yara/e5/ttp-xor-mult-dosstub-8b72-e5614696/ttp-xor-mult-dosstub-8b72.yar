rule TTP_XOR_MULT_DOSStub_8b72 {
  strings:
    $key_8b72 = { df 1a [2] ab 02 [2] ec 00 [2] ab 11 [2] e5 1d [2] e9 17 [2] fe 1c [2] e5 52 [2] d8 }

  condition:
    any of them
}