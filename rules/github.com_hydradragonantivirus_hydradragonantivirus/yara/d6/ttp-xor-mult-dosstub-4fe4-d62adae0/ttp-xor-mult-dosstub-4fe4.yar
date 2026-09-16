rule TTP_XOR_MULT_DOSStub_4fe4 {
  strings:
    $key_4fe4 = { 1b 8c [2] 6f 94 [2] 28 96 [2] 6f 87 [2] 21 8b [2] 2d 81 [2] 3a 8a [2] 21 c4 [2] 1c }

  condition:
    any of them
}