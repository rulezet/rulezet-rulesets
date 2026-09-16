rule TTP_XOR_MULT_DOSStub_17e7 {
  strings:
    $key_17e7 = { 43 8f [2] 37 97 [2] 70 95 [2] 37 84 [2] 79 88 [2] 75 82 [2] 62 89 [2] 79 c7 [2] 44 }

  condition:
    any of them
}