rule TTP_XOR_MULT_DOSStub_4e7d {
  strings:
    $key_4e7d = { 1a 15 [2] 6e 0d [2] 29 0f [2] 6e 1e [2] 20 12 [2] 2c 18 [2] 3b 13 [2] 20 5d [2] 1d }

  condition:
    any of them
}