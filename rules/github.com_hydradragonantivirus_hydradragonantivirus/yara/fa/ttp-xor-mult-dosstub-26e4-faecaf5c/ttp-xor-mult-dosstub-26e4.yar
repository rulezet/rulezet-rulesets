rule TTP_XOR_MULT_DOSStub_26e4 {
  strings:
    $key_26e4 = { 72 8c [2] 06 94 [2] 41 96 [2] 06 87 [2] 48 8b [2] 44 81 [2] 53 8a [2] 48 c4 [2] 75 }

  condition:
    any of them
}