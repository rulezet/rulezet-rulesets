rule TTP_XOR_MULT_DOSStub_18e4 {
  strings:
    $key_18e4 = { 4c 8c [2] 38 94 [2] 7f 96 [2] 38 87 [2] 76 8b [2] 7a 81 [2] 6d 8a [2] 76 c4 [2] 4b }

  condition:
    any of them
}