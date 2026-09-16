rule TTP_XOR_MULT_DOSStub_13df {
  strings:
    $key_13df = { 47 b7 [2] 33 af [2] 74 ad [2] 33 bc [2] 7d b0 [2] 71 ba [2] 66 b1 [2] 7d ff [2] 40 }

  condition:
    any of them
}