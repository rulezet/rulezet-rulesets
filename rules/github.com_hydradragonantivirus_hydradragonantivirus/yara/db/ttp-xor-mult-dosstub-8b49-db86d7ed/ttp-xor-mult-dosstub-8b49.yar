rule TTP_XOR_MULT_DOSStub_8b49 {
  strings:
    $key_8b49 = { df 21 [2] ab 39 [2] ec 3b [2] ab 2a [2] e5 26 [2] e9 2c [2] fe 27 [2] e5 69 [2] d8 }

  condition:
    any of them
}