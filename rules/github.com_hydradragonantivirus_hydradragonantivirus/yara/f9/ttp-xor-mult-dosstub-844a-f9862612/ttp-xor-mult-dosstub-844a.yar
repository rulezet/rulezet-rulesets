rule TTP_XOR_MULT_DOSStub_844a {
  strings:
    $key_844a = { d0 22 [2] a4 3a [2] e3 38 [2] a4 29 [2] ea 25 [2] e6 2f [2] f1 24 [2] ea 6a [2] d7 }

  condition:
    any of them
}