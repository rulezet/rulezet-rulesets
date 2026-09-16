rule TTP_XOR_MULT_DOSStub_1346 {
  strings:
    $key_1346 = { 47 2e [2] 33 36 [2] 74 34 [2] 33 25 [2] 7d 29 [2] 71 23 [2] 66 28 [2] 7d 66 [2] 40 }

  condition:
    any of them
}