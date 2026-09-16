rule TTP_XOR_MULT_DOSStub_4e50 {
  strings:
    $key_4e50 = { 1a 38 [2] 6e 20 [2] 29 22 [2] 6e 33 [2] 20 3f [2] 2c 35 [2] 3b 3e [2] 20 70 [2] 1d }

  condition:
    any of them
}