rule TTP_XOR_MULT_DOSStub_7ae4 {
  strings:
    $key_7ae4 = { 2e 8c [2] 5a 94 [2] 1d 96 [2] 5a 87 [2] 14 8b [2] 18 81 [2] 0f 8a [2] 14 c4 [2] 29 }

  condition:
    any of them
}