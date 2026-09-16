rule TTP_XOR_MULT_DOSStub_3edf {
  strings:
    $key_3edf = { 6a b7 [2] 1e af [2] 59 ad [2] 1e bc [2] 50 b0 [2] 5c ba [2] 4b b1 [2] 50 ff [2] 6d }

  condition:
    any of them
}