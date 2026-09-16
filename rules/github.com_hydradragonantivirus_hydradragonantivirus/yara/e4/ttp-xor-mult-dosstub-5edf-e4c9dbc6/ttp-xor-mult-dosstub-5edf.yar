rule TTP_XOR_MULT_DOSStub_5edf {
  strings:
    $key_5edf = { 0a b7 [2] 7e af [2] 39 ad [2] 7e bc [2] 30 b0 [2] 3c ba [2] 2b b1 [2] 30 ff [2] 0d }

  condition:
    any of them
}