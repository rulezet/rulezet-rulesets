rule TTP_XOR_MULT_DOSStub_4ee0 {
  strings:
    $key_4ee0 = { 1a 88 [2] 6e 90 [2] 29 92 [2] 6e 83 [2] 20 8f [2] 2c 85 [2] 3b 8e [2] 20 c0 [2] 1d }

  condition:
    any of them
}