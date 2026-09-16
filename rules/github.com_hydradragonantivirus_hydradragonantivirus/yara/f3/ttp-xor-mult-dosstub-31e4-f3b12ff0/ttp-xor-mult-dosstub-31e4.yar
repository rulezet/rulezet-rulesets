rule TTP_XOR_MULT_DOSStub_31e4 {
  strings:
    $key_31e4 = { 65 8c [2] 11 94 [2] 56 96 [2] 11 87 [2] 5f 8b [2] 53 81 [2] 44 8a [2] 5f c4 [2] 62 }

  condition:
    any of them
}