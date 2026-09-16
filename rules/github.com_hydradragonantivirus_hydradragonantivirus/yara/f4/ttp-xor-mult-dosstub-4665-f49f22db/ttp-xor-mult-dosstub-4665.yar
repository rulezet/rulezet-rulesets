rule TTP_XOR_MULT_DOSStub_4665 {
  strings:
    $key_4665 = { 12 0d [2] 66 15 [2] 21 17 [2] 66 06 [2] 28 0a [2] 24 00 [2] 33 0b [2] 28 45 [2] 15 }

  condition:
    any of them
}