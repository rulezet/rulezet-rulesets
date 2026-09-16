rule TTP_XOR_MULT_DOSStub_4117 {
  strings:
    $key_4117 = { 15 7f [2] 61 67 [2] 26 65 [2] 61 74 [2] 2f 78 [2] 23 72 [2] 34 79 [2] 2f 37 [2] 12 }

  condition:
    any of them
}