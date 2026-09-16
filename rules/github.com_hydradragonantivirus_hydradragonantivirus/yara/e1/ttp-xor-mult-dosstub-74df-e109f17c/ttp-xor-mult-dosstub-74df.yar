rule TTP_XOR_MULT_DOSStub_74df {
  strings:
    $key_74df = { 20 b7 [2] 54 af [2] 13 ad [2] 54 bc [2] 1a b0 [2] 16 ba [2] 01 b1 [2] 1a ff [2] 27 }

  condition:
    any of them
}