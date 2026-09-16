rule TTP_XOR_MULT_DOSStub_29df {
  strings:
    $key_29df = { 7d b7 [2] 09 af [2] 4e ad [2] 09 bc [2] 47 b0 [2] 4b ba [2] 5c b1 [2] 47 ff [2] 7a }

  condition:
    any of them
}