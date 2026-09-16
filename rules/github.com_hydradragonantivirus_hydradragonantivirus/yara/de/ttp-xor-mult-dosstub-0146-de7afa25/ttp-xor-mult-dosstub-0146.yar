rule TTP_XOR_MULT_DOSStub_0146 {
  strings:
    $key_0146 = { 55 2e [2] 21 36 [2] 66 34 [2] 21 25 [2] 6f 29 [2] 63 23 [2] 74 28 [2] 6f 66 [2] 52 }

  condition:
    any of them
}