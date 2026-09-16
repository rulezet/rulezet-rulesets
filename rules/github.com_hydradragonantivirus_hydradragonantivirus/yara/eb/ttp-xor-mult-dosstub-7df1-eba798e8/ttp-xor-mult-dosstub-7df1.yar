rule TTP_XOR_MULT_DOSStub_7df1 {
  strings:
    $key_7df1 = { 29 99 [2] 5d 81 [2] 1a 83 [2] 5d 92 [2] 13 9e [2] 1f 94 [2] 08 9f [2] 13 d1 [2] 2e }

  condition:
    any of them
}