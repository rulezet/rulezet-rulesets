rule TTP_XOR_MULT_DOSStub_3cdc {
  strings:
    $key_3cdc = { 68 b4 [2] 1c ac [2] 5b ae [2] 1c bf [2] 52 b3 [2] 5e b9 [2] 49 b2 [2] 52 fc [2] 6f }

  condition:
    any of them
}