rule TTP_XOR_MULT_DOSStub_6cdc {
  strings:
    $key_6cdc = { 38 b4 [2] 4c ac [2] 0b ae [2] 4c bf [2] 02 b3 [2] 0e b9 [2] 19 b2 [2] 02 fc [2] 3f }

  condition:
    any of them
}