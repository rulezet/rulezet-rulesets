rule TTP_XOR_MULT_DOSStub_1706 {
  strings:
    $key_1706 = { 43 6e [2] 37 76 [2] 70 74 [2] 37 65 [2] 79 69 [2] 75 63 [2] 62 68 [2] 79 26 [2] 44 }

  condition:
    any of them
}