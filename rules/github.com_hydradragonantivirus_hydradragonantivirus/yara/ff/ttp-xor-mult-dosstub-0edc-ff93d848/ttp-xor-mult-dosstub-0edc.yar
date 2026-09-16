rule TTP_XOR_MULT_DOSStub_0edc {
  strings:
    $key_0edc = { 5a b4 [2] 2e ac [2] 69 ae [2] 2e bf [2] 60 b3 [2] 6c b9 [2] 7b b2 [2] 60 fc [2] 5d }

  condition:
    any of them
}