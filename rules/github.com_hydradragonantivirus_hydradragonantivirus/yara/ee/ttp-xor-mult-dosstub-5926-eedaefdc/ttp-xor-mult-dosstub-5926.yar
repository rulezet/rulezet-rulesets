rule TTP_XOR_MULT_DOSStub_5926 {
  strings:
    $key_5926 = { 0d 4e [2] 79 56 [2] 3e 54 [2] 79 45 [2] 37 49 [2] 3b 43 [2] 2c 48 [2] 37 06 [2] 0a }

  condition:
    any of them
}