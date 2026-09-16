rule TTP_XOR_MULT_DOSStub_5df7 {
  strings:
    $key_5df7 = { 09 9f [2] 7d 87 [2] 3a 85 [2] 7d 94 [2] 33 98 [2] 3f 92 [2] 28 99 [2] 33 d7 [2] 0e }

  condition:
    any of them
}