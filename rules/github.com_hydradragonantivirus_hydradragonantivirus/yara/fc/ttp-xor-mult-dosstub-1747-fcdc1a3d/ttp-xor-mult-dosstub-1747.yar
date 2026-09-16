rule TTP_XOR_MULT_DOSStub_1747 {
  strings:
    $key_1747 = { 43 2f [2] 37 37 [2] 70 35 [2] 37 24 [2] 79 28 [2] 75 22 [2] 62 29 [2] 79 67 [2] 44 }

  condition:
    any of them
}