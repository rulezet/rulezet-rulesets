rule TTP_XOR_MULT_DOSStub_a3df {
  strings:
    $key_a3df = { f7 b7 [2] 83 af [2] c4 ad [2] 83 bc [2] cd b0 [2] c1 ba [2] d6 b1 [2] cd ff [2] f0 }

  condition:
    any of them
}