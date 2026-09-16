rule TTP_XOR_MULT_DOSStub_4251 {
  strings:
    $key_4251 = { 16 39 [2] 62 21 [2] 25 23 [2] 62 32 [2] 2c 3e [2] 20 34 [2] 37 3f [2] 2c 71 [2] 11 }

  condition:
    any of them
}