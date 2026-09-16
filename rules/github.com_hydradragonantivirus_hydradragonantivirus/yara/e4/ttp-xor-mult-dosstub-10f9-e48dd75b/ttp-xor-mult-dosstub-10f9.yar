rule TTP_XOR_MULT_DOSStub_10f9 {
  strings:
    $key_10f9 = { 44 91 [2] 30 89 [2] 77 8b [2] 30 9a [2] 7e 96 [2] 72 9c [2] 65 97 [2] 7e d9 [2] 43 }

  condition:
    any of them
}