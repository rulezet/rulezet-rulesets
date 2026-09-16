rule TTP_XOR_MULT_DOSStub_70f9 {
  strings:
    $key_70f9 = { 24 91 [2] 50 89 [2] 17 8b [2] 50 9a [2] 1e 96 [2] 12 9c [2] 05 97 [2] 1e d9 [2] 23 }

  condition:
    any of them
}