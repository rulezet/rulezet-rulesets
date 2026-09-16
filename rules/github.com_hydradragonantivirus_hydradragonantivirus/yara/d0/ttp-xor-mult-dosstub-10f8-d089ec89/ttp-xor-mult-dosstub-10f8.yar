rule TTP_XOR_MULT_DOSStub_10f8 {
  strings:
    $key_10f8 = { 44 90 [2] 30 88 [2] 77 8a [2] 30 9b [2] 7e 97 [2] 72 9d [2] 65 96 [2] 7e d8 [2] 43 }

  condition:
    any of them
}