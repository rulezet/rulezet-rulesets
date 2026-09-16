rule TTP_XOR_MULT_DOSStub_4e0b {
  strings:
    $key_4e0b = { 1a 63 [2] 6e 7b [2] 29 79 [2] 6e 68 [2] 20 64 [2] 2c 6e [2] 3b 65 [2] 20 2b [2] 1d }

  condition:
    any of them
}