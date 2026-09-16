rule TTP_XOR_MULT_DOSStub_4664 {
  strings:
    $key_4664 = { 12 0c [2] 66 14 [2] 21 16 [2] 66 07 [2] 28 0b [2] 24 01 [2] 33 0a [2] 28 44 [2] 15 }

  condition:
    any of them
}