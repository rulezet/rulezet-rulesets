rule TTP_XOR_MULT_DOSStub_4e21 {
  strings:
    $key_4e21 = { 1a 49 [2] 6e 51 [2] 29 53 [2] 6e 42 [2] 20 4e [2] 2c 44 [2] 3b 4f [2] 20 01 [2] 1d }

  condition:
    any of them
}