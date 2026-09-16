rule TTP_XOR_MULT_DOSStub_4267 {
  strings:
    $key_4267 = { 16 0f [2] 62 17 [2] 25 15 [2] 62 04 [2] 2c 08 [2] 20 02 [2] 37 09 [2] 2c 47 [2] 11 }

  condition:
    any of them
}