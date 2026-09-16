rule TTP_XOR_MULT_DOSStub_44e4 {
  strings:
    $key_44e4 = { 10 8c [2] 64 94 [2] 23 96 [2] 64 87 [2] 2a 8b [2] 26 81 [2] 31 8a [2] 2a c4 [2] 17 }

  condition:
    any of them
}