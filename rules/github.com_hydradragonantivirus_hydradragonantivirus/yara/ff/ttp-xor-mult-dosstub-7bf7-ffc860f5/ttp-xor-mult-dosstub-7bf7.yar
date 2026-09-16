rule TTP_XOR_MULT_DOSStub_7bf7 {
  strings:
    $key_7bf7 = { 2f 9f [2] 5b 87 [2] 1c 85 [2] 5b 94 [2] 15 98 [2] 19 92 [2] 0e 99 [2] 15 d7 [2] 28 }

  condition:
    any of them
}