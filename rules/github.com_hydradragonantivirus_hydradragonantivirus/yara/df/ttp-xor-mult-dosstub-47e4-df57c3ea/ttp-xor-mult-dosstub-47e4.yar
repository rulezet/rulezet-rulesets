rule TTP_XOR_MULT_DOSStub_47e4 {
  strings:
    $key_47e4 = { 13 8c [2] 67 94 [2] 20 96 [2] 67 87 [2] 29 8b [2] 25 81 [2] 32 8a [2] 29 c4 [2] 14 }

  condition:
    any of them
}