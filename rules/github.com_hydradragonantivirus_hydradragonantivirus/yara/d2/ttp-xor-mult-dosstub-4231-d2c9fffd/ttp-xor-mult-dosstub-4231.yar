rule TTP_XOR_MULT_DOSStub_4231 {
  strings:
    $key_4231 = { 16 59 [2] 62 41 [2] 25 43 [2] 62 52 [2] 2c 5e [2] 20 54 [2] 37 5f [2] 2c 11 [2] 11 }

  condition:
    any of them
}