rule TTP_XOR_MULT_DOSStub_1554 {
  strings:
    $key_1554 = { 41 3c [2] 35 24 [2] 72 26 [2] 35 37 [2] 7b 3b [2] 77 31 [2] 60 3a [2] 7b 74 [2] 46 }

  condition:
    any of them
}