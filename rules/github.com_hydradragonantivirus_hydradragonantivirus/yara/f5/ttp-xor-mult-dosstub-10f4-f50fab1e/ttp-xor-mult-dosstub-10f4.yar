rule TTP_XOR_MULT_DOSStub_10f4 {
  strings:
    $key_10f4 = { 44 9c [2] 30 84 [2] 77 86 [2] 30 97 [2] 7e 9b [2] 72 91 [2] 65 9a [2] 7e d4 [2] 43 }

  condition:
    any of them
}