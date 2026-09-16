rule TTP_XOR_MULT_DOSStub_4a46 {
  strings:
    $key_4a46 = { 1e 2e [2] 6a 36 [2] 2d 34 [2] 6a 25 [2] 24 29 [2] 28 23 [2] 3f 28 [2] 24 66 [2] 19 }

  condition:
    any of them
}