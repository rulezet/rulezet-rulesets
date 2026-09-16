rule TTP_XOR_MULT_DOSStub_32df {
  strings:
    $key_32df = { 66 b7 [2] 12 af [2] 55 ad [2] 12 bc [2] 5c b0 [2] 50 ba [2] 47 b1 [2] 5c ff [2] 61 }

  condition:
    any of them
}