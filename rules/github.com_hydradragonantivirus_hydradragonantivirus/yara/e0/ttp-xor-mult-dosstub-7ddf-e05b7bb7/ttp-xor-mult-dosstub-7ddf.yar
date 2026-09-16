rule TTP_XOR_MULT_DOSStub_7ddf {
  strings:
    $key_7ddf = { 29 b7 [2] 5d af [2] 1a ad [2] 5d bc [2] 13 b0 [2] 1f ba [2] 08 b1 [2] 13 ff [2] 2e }

  condition:
    any of them
}