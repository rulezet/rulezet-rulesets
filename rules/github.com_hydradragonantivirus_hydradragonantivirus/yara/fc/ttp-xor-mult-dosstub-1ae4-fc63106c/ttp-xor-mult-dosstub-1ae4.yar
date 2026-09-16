rule TTP_XOR_MULT_DOSStub_1ae4 {
  strings:
    $key_1ae4 = { 4e 8c [2] 3a 94 [2] 7d 96 [2] 3a 87 [2] 74 8b [2] 78 81 [2] 6f 8a [2] 74 c4 [2] 49 }

  condition:
    any of them
}