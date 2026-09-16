rule TTP_XOR_MULT_DOSStub_38df {
  strings:
    $key_38df = { 6c b7 [2] 18 af [2] 5f ad [2] 18 bc [2] 56 b0 [2] 5a ba [2] 4d b1 [2] 56 ff [2] 6b }

  condition:
    any of them
}