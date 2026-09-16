rule TTP_XOR_MULT_DOSStub_4617 {
  strings:
    $key_4617 = { 12 7f [2] 66 67 [2] 21 65 [2] 66 74 [2] 28 78 [2] 24 72 [2] 33 79 [2] 28 37 [2] 15 }

  condition:
    any of them
}