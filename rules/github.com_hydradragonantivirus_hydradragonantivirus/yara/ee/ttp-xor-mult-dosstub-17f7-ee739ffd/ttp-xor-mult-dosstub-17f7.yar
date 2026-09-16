rule TTP_XOR_MULT_DOSStub_17f7 {
  strings:
    $key_17f7 = { 43 9f [2] 37 87 [2] 70 85 [2] 37 94 [2] 79 98 [2] 75 92 [2] 62 99 [2] 79 d7 [2] 44 }

  condition:
    any of them
}