rule TTP_XOR_MULT_DOSStub_1751 {
  strings:
    $key_1751 = { 43 39 [2] 37 21 [2] 70 23 [2] 37 32 [2] 79 3e [2] 75 34 [2] 62 3f [2] 79 71 [2] 44 }

  condition:
    any of them
}