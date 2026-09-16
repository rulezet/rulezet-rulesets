rule TTP_XOR_MULT_DOSStub_4221 {
  strings:
    $key_4221 = { 16 49 [2] 62 51 [2] 25 53 [2] 62 42 [2] 2c 4e [2] 20 44 [2] 37 4f [2] 2c 01 [2] 11 }

  condition:
    any of them
}