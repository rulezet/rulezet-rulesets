rule TTP_XOR_MULT_DOSStub_17f6 {
  strings:
    $key_17f6 = { 43 9e [2] 37 86 [2] 70 84 [2] 37 95 [2] 79 99 [2] 75 93 [2] 62 98 [2] 79 d6 [2] 44 }

  condition:
    any of them
}