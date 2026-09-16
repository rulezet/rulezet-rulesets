rule TTP_XOR_MULT_DOSStub_59df {
  strings:
    $key_59df = { 0d b7 [2] 79 af [2] 3e ad [2] 79 bc [2] 37 b0 [2] 3b ba [2] 2c b1 [2] 37 ff [2] 0a }

  condition:
    any of them
}