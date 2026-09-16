rule TTP_XOR_MULT_DOSStub_788a {
  strings:
    $key_788a = { 2c e2 [2] 58 fa [2] 1f f8 [2] 58 e9 [2] 16 e5 [2] 1a ef [2] 0d e4 [2] 16 aa [2] 2b }

  condition:
    any of them
}