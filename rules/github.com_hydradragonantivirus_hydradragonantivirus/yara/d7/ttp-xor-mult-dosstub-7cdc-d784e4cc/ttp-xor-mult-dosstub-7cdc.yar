rule TTP_XOR_MULT_DOSStub_7cdc {
  strings:
    $key_7cdc = { 28 b4 [2] 5c ac [2] 1b ae [2] 5c bf [2] 12 b3 [2] 1e b9 [2] 09 b2 [2] 12 fc [2] 2f }

  condition:
    any of them
}