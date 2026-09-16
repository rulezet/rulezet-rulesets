rule TTP_XOR_MULT_DOSStub_428c {
  strings:
    $key_428c = { 16 e4 [2] 62 fc [2] 25 fe [2] 62 ef [2] 2c e3 [2] 20 e9 [2] 37 e2 [2] 2c ac [2] 11 }

  condition:
    any of them
}