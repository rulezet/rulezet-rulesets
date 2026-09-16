rule TTP_XOR_MULT_DOSStub_4e01 {
  strings:
    $key_4e01 = { 1a 69 [2] 6e 71 [2] 29 73 [2] 6e 62 [2] 20 6e [2] 2c 64 [2] 3b 6f [2] 20 21 [2] 1d }

  condition:
    any of them
}