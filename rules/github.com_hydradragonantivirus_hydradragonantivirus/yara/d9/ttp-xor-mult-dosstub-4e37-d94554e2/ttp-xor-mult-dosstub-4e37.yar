rule TTP_XOR_MULT_DOSStub_4e37 {
  strings:
    $key_4e37 = { 1a 5f [2] 6e 47 [2] 29 45 [2] 6e 54 [2] 20 58 [2] 2c 52 [2] 3b 59 [2] 20 17 [2] 1d }

  condition:
    any of them
}