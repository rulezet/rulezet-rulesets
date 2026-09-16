rule TTP_XOR_MULT_DOSStub_4e41 {
  strings:
    $key_4e41 = { 1a 29 [2] 6e 31 [2] 29 33 [2] 6e 22 [2] 20 2e [2] 2c 24 [2] 3b 2f [2] 20 61 [2] 1d }

  condition:
    any of them
}