rule TTP_XOR_MULT_DOSStub_1754 {
  strings:
    $key_1754 = { 43 3c [2] 37 24 [2] 70 26 [2] 37 37 [2] 79 3b [2] 75 31 [2] 62 3a [2] 79 74 [2] 44 }

  condition:
    any of them
}