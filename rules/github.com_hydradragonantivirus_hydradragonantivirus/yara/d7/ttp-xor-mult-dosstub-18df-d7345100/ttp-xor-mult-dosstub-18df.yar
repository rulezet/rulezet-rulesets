rule TTP_XOR_MULT_DOSStub_18df {
  strings:
    $key_18df = { 4c b7 [2] 38 af [2] 7f ad [2] 38 bc [2] 76 b0 [2] 7a ba [2] 6d b1 [2] 76 ff [2] 4b }

  condition:
    any of them
}