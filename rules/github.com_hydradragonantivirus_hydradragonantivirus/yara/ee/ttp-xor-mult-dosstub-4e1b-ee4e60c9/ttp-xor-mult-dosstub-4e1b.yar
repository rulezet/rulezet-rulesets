rule TTP_XOR_MULT_DOSStub_4e1b {
  strings:
    $key_4e1b = { 1a 73 [2] 6e 6b [2] 29 69 [2] 6e 78 [2] 20 74 [2] 2c 7e [2] 3b 75 [2] 20 3b [2] 1d }

  condition:
    any of them
}