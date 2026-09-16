rule TTP_XOR_MULT_DOSStub_1569 {
  strings:
    $key_1569 = { 41 01 [2] 35 19 [2] 72 1b [2] 35 0a [2] 7b 06 [2] 77 0c [2] 60 07 [2] 7b 49 [2] 46 }

  condition:
    any of them
}