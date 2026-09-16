rule TTP_XOR_MULT_DOSStub_7edc {
  strings:
    $key_7edc = { 2a b4 [2] 5e ac [2] 19 ae [2] 5e bf [2] 10 b3 [2] 1c b9 [2] 0b b2 [2] 10 fc [2] 2d }

  condition:
    any of them
}