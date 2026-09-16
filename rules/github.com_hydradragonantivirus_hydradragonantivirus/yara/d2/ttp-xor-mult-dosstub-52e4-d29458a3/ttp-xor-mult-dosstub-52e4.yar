rule TTP_XOR_MULT_DOSStub_52e4 {
  strings:
    $key_52e4 = { 06 8c [2] 72 94 [2] 35 96 [2] 72 87 [2] 3c 8b [2] 30 81 [2] 27 8a [2] 3c c4 [2] 01 }

  condition:
    any of them
}