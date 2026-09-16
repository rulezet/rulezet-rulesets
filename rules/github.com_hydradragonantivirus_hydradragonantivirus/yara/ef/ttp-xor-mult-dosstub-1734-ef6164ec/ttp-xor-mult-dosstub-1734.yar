rule TTP_XOR_MULT_DOSStub_1734 {
  strings:
    $key_1734 = { 43 5c [2] 37 44 [2] 70 46 [2] 37 57 [2] 79 5b [2] 75 51 [2] 62 5a [2] 79 14 [2] 44 }

  condition:
    any of them
}