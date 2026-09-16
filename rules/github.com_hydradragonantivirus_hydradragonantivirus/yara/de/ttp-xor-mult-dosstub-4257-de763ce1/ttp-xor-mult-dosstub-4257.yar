rule TTP_XOR_MULT_DOSStub_4257 {
  strings:
    $key_4257 = { 16 3f [2] 62 27 [2] 25 25 [2] 62 34 [2] 2c 38 [2] 20 32 [2] 37 39 [2] 2c 77 [2] 11 }

  condition:
    any of them
}