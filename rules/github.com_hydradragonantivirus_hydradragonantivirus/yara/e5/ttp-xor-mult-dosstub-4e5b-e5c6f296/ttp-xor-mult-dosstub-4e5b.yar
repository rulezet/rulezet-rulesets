rule TTP_XOR_MULT_DOSStub_4e5b {
  strings:
    $key_4e5b = { 1a 33 [2] 6e 2b [2] 29 29 [2] 6e 38 [2] 20 34 [2] 2c 3e [2] 3b 35 [2] 20 7b [2] 1d }

  condition:
    any of them
}