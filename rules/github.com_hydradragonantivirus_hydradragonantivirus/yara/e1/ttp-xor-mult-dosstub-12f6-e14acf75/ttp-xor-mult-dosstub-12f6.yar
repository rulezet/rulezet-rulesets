rule TTP_XOR_MULT_DOSStub_12f6 {
  strings:
    $key_12f6 = { 46 9e [2] 32 86 [2] 75 84 [2] 32 95 [2] 7c 99 [2] 70 93 [2] 67 98 [2] 7c d6 [2] 41 }

  condition:
    any of them
}