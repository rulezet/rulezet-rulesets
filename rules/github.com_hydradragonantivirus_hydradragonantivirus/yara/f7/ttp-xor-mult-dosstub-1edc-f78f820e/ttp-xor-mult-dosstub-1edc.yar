rule TTP_XOR_MULT_DOSStub_1edc {
  strings:
    $key_1edc = { 4a b4 [2] 3e ac [2] 79 ae [2] 3e bf [2] 70 b3 [2] 7c b9 [2] 6b b2 [2] 70 fc [2] 4d }

  condition:
    any of them
}