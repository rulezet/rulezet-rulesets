rule TTP_XOR_MULT_DOSStub_04df {
  strings:
    $key_04df = { 50 b7 [2] 24 af [2] 63 ad [2] 24 bc [2] 6a b0 [2] 66 ba [2] 71 b1 [2] 6a ff [2] 57 }

  condition:
    any of them
}