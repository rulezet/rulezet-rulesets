rule TTP_XOR_MULT_DOSStub_60f9 {
  strings:
    $key_60f9 = { 34 91 [2] 40 89 [2] 07 8b [2] 40 9a [2] 0e 96 [2] 02 9c [2] 15 97 [2] 0e d9 [2] 33 }

  condition:
    any of them
}