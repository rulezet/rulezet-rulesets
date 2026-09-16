rule TTP_XOR_MULT_DOSStub_5a46 {
  strings:
    $key_5a46 = { 0e 2e [2] 7a 36 [2] 3d 34 [2] 7a 25 [2] 34 29 [2] 38 23 [2] 2f 28 [2] 34 66 [2] 09 }

  condition:
    any of them
}