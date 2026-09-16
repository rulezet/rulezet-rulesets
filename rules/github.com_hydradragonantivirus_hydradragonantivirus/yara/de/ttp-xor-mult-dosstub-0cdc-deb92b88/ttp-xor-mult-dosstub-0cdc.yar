rule TTP_XOR_MULT_DOSStub_0cdc {
  strings:
    $key_0cdc = { 58 b4 [2] 2c ac [2] 6b ae [2] 2c bf [2] 62 b3 [2] 6e b9 [2] 79 b2 [2] 62 fc [2] 5f }

  condition:
    any of them
}