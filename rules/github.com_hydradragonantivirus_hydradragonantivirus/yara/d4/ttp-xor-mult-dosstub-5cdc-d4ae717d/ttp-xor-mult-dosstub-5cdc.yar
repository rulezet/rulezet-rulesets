rule TTP_XOR_MULT_DOSStub_5cdc {
  strings:
    $key_5cdc = { 08 b4 [2] 7c ac [2] 3b ae [2] 7c bf [2] 32 b3 [2] 3e b9 [2] 29 b2 [2] 32 fc [2] 0f }

  condition:
    any of them
}