rule TTP_XOR_MULT_DOSStub_1bdc {
  strings:
    $key_1bdc = { 4f b4 [2] 3b ac [2] 7c ae [2] 3b bf [2] 75 b3 [2] 79 b9 [2] 6e b2 [2] 75 fc [2] 48 }

  condition:
    any of them
}