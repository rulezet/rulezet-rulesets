rule TTP_XOR_MULT_DOSStub_22f7 {
  strings:
    $key_22f7 = { 76 9f [2] 02 87 [2] 45 85 [2] 02 94 [2] 4c 98 [2] 40 92 [2] 57 99 [2] 4c d7 [2] 71 }

  condition:
    any of them
}