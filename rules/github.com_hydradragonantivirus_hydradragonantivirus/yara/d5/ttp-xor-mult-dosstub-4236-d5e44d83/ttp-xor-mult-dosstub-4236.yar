rule TTP_XOR_MULT_DOSStub_4236 {
  strings:
    $key_4236 = { 16 5e [2] 62 46 [2] 25 44 [2] 62 55 [2] 2c 59 [2] 20 53 [2] 37 58 [2] 2c 16 [2] 11 }

  condition:
    any of them
}