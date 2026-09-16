rule TTP_XOR_MULT_DOSStub_4e00 {
  strings:
    $key_4e00 = { 1a 68 [2] 6e 70 [2] 29 72 [2] 6e 63 [2] 20 6f [2] 2c 65 [2] 3b 6e [2] 20 20 [2] 1d }

  condition:
    any of them
}