rule TTP_XOR_MULT_DOSStub_4e10 {
  strings:
    $key_4e10 = { 1a 78 [2] 6e 60 [2] 29 62 [2] 6e 73 [2] 20 7f [2] 2c 75 [2] 3b 7e [2] 20 30 [2] 1d }

  condition:
    any of them
}