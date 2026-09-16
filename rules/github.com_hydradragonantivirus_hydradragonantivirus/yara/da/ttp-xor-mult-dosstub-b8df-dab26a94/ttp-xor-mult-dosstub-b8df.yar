rule TTP_XOR_MULT_DOSStub_b8df {
  strings:
    $key_b8df = { ec b7 [2] 98 af [2] df ad [2] 98 bc [2] d6 b0 [2] da ba [2] cd b1 [2] d6 ff [2] eb }

  condition:
    any of them
}