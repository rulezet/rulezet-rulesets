rule TTP_XOR_MULT_DOSStub_4e20 {
  strings:
    $key_4e20 = { 1a 48 [2] 6e 50 [2] 29 52 [2] 6e 43 [2] 20 4f [2] 2c 45 [2] 3b 4e [2] 20 00 [2] 1d }

  condition:
    any of them
}