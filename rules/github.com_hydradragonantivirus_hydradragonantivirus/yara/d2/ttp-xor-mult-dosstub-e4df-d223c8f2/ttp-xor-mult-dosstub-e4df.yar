rule TTP_XOR_MULT_DOSStub_e4df {
  strings:
    $key_e4df = { b0 b7 [2] c4 af [2] 83 ad [2] c4 bc [2] 8a b0 [2] 86 ba [2] 91 b1 [2] 8a ff [2] b7 }

  condition:
    any of them
}