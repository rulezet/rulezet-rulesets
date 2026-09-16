rule TTP_XOR_MULT_DOSStub_841a {
  strings:
    $key_841a = { d0 72 [2] a4 6a [2] e3 68 [2] a4 79 [2] ea 75 [2] e6 7f [2] f1 74 [2] ea 3a [2] d7 }

  condition:
    any of them
}