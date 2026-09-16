rule TTP_XOR_MULT_DOSStub_10f5 {
  strings:
    $key_10f5 = { 44 9d [2] 30 85 [2] 77 87 [2] 30 96 [2] 7e 9a [2] 72 90 [2] 65 9b [2] 7e d5 [2] 43 }

  condition:
    any of them
}