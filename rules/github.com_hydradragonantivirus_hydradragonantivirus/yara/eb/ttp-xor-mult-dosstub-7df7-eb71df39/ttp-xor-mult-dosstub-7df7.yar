rule TTP_XOR_MULT_DOSStub_7df7 {
  strings:
    $key_7df7 = { 29 9f [2] 5d 87 [2] 1a 85 [2] 5d 94 [2] 13 98 [2] 1f 92 [2] 08 99 [2] 13 d7 [2] 2e }

  condition:
    any of them
}