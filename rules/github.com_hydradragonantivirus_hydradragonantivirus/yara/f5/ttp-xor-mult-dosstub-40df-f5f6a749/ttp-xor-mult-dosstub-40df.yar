rule TTP_XOR_MULT_DOSStub_40df {
  strings:
    $key_40df = { 14 b7 [2] 60 af [2] 27 ad [2] 60 bc [2] 2e b0 [2] 22 ba [2] 35 b1 [2] 2e ff [2] 13 }

  condition:
    any of them
}