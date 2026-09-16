rule TTP_XOR_MULT_DOSStub_64df {
  strings:
    $key_64df = { 30 b7 [2] 44 af [2] 03 ad [2] 44 bc [2] 0a b0 [2] 06 ba [2] 11 b1 [2] 0a ff [2] 37 }

  condition:
    any of them
}