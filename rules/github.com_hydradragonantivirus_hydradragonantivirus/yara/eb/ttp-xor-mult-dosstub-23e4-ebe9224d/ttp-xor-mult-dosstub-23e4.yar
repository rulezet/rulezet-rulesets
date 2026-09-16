rule TTP_XOR_MULT_DOSStub_23e4 {
  strings:
    $key_23e4 = { 77 8c [2] 03 94 [2] 44 96 [2] 03 87 [2] 4d 8b [2] 41 81 [2] 56 8a [2] 4d c4 [2] 70 }

  condition:
    any of them
}