rule TTP_XOR_MULT_DOSStub_2ce4 {
  strings:
    $key_2ce4 = { 78 8c [2] 0c 94 [2] 4b 96 [2] 0c 87 [2] 42 8b [2] 4e 81 [2] 59 8a [2] 42 c4 [2] 7f }

  condition:
    any of them
}