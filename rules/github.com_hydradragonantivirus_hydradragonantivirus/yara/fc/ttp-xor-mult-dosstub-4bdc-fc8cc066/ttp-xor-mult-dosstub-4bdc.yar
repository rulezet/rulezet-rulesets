rule TTP_XOR_MULT_DOSStub_4bdc {
  strings:
    $key_4bdc = { 1f b4 [2] 6b ac [2] 2c ae [2] 6b bf [2] 25 b3 [2] 29 b9 [2] 3e b2 [2] 25 fc [2] 18 }

  condition:
    any of them
}