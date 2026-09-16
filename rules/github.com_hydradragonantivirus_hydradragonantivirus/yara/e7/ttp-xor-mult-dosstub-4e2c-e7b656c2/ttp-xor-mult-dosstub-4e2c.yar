rule TTP_XOR_MULT_DOSStub_4e2c {
  strings:
    $key_4e2c = { 1a 44 [2] 6e 5c [2] 29 5e [2] 6e 4f [2] 20 43 [2] 2c 49 [2] 3b 42 [2] 20 0c [2] 1d }

  condition:
    any of them
}