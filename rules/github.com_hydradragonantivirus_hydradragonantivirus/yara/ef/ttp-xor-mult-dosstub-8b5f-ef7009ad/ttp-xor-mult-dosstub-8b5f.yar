rule TTP_XOR_MULT_DOSStub_8b5f {
  strings:
    $key_8b5f = { df 37 [2] ab 2f [2] ec 2d [2] ab 3c [2] e5 30 [2] e9 3a [2] fe 31 [2] e5 7f [2] d8 }

  condition:
    any of them
}