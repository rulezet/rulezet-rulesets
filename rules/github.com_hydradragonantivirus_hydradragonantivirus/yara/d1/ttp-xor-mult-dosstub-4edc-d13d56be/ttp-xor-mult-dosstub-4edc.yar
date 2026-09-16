rule TTP_XOR_MULT_DOSStub_4edc {
  strings:
    $key_4edc = { 1a b4 [2] 6e ac [2] 29 ae [2] 6e bf [2] 20 b3 [2] 2c b9 [2] 3b b2 [2] 20 fc [2] 1d }

  condition:
    any of them
}