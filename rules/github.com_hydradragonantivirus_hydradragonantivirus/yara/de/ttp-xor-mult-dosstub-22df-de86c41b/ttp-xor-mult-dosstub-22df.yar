rule TTP_XOR_MULT_DOSStub_22df {
  strings:
    $key_22df = { 76 b7 [2] 02 af [2] 45 ad [2] 02 bc [2] 4c b0 [2] 40 ba [2] 57 b1 [2] 4c ff [2] 71 }

  condition:
    any of them
}