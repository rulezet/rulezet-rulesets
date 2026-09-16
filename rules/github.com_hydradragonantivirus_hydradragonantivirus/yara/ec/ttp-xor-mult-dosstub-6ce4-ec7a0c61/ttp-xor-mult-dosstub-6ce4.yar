rule TTP_XOR_MULT_DOSStub_6ce4 {
  strings:
    $key_6ce4 = { 38 8c [2] 4c 94 [2] 0b 96 [2] 4c 87 [2] 02 8b [2] 0e 81 [2] 19 8a [2] 02 c4 [2] 3f }

  condition:
    any of them
}