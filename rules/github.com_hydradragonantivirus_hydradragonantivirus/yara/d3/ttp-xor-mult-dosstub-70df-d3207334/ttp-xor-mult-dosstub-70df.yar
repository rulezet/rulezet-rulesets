rule TTP_XOR_MULT_DOSStub_70df {
  strings:
    $key_70df = { 24 b7 [2] 50 af [2] 17 ad [2] 50 bc [2] 1e b0 [2] 12 ba [2] 05 b1 [2] 1e ff [2] 23 }

  condition:
    any of them
}