rule TTP_XOR_MULT_DOSStub_8b5a {
  strings:
    $key_8b5a = { df 32 [2] ab 2a [2] ec 28 [2] ab 39 [2] e5 35 [2] e9 3f [2] fe 34 [2] e5 7a [2] d8 }

  condition:
    any of them
}