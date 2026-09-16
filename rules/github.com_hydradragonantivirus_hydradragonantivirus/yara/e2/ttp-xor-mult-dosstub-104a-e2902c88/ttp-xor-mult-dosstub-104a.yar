rule TTP_XOR_MULT_DOSStub_104a {
  strings:
    $key_104a = { 44 22 [2] 30 3a [2] 77 38 [2] 30 29 [2] 7e 25 [2] 72 2f [2] 65 24 [2] 7e 6a [2] 43 }

  condition:
    any of them
}