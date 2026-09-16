rule TTP_XOR_MULT_DOSStub_4017 {
  strings:
    $key_4017 = { 14 7f [2] 60 67 [2] 27 65 [2] 60 74 [2] 2e 78 [2] 22 72 [2] 35 79 [2] 2e 37 [2] 13 }

  condition:
    any of them
}