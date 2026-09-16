rule TTP_XOR_MULT_DOSStub_ca1a {
  strings:
    $key_ca1a = { 9e 72 [2] ea 6a [2] ad 68 [2] ea 79 [2] a4 75 [2] a8 7f [2] bf 74 [2] a4 3a [2] 99 }

  condition:
    any of them
}