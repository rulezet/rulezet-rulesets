rule TTP_XOR_MULT_DOSStub_782d {
  strings:
    $key_782d = { 2c 45 [2] 58 5d [2] 1f 5f [2] 58 4e [2] 16 42 [2] 1a 48 [2] 0d 43 [2] 16 0d [2] 2b }

  condition:
    any of them
}