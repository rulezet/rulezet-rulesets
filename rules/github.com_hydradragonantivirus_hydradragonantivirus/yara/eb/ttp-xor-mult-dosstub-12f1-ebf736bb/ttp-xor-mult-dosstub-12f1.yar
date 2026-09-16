rule TTP_XOR_MULT_DOSStub_12f1 {
  strings:
    $key_12f1 = { 46 99 [2] 32 81 [2] 75 83 [2] 32 92 [2] 7c 9e [2] 70 94 [2] 67 9f [2] 7c d1 [2] 41 }

  condition:
    any of them
}