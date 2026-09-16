rule TTP_XOR_MULT_DOSStub_0edf {
  strings:
    $key_0edf = { 5a b7 [2] 2e af [2] 69 ad [2] 2e bc [2] 60 b0 [2] 6c ba [2] 7b b1 [2] 60 ff [2] 5d }

  condition:
    any of them
}