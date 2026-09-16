rule TTP_XOR_MULT_DOSStub_8b56 {
  strings:
    $key_8b56 = { df 3e [2] ab 26 [2] ec 24 [2] ab 35 [2] e5 39 [2] e9 33 [2] fe 38 [2] e5 76 [2] d8 }

  condition:
    any of them
}