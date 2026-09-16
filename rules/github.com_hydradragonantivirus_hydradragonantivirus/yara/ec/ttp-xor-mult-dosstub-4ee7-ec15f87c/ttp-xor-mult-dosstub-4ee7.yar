rule TTP_XOR_MULT_DOSStub_4ee7 {
  strings:
    $key_4ee7 = { 1a 8f [2] 6e 97 [2] 29 95 [2] 6e 84 [2] 20 88 [2] 2c 82 [2] 3b 89 [2] 20 c7 [2] 1d }

  condition:
    any of them
}