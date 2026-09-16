rule TTP_XOR_MULT_DOSStub_0446 {
  strings:
    $key_0446 = { 50 2e [2] 24 36 [2] 63 34 [2] 24 25 [2] 6a 29 [2] 66 23 [2] 71 28 [2] 6a 66 [2] 57 }

  condition:
    any of them
}