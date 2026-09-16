rule TTP_XOR_MULT_DOSStub_1edf {
  strings:
    $key_1edf = { 4a b7 [2] 3e af [2] 79 ad [2] 3e bc [2] 70 b0 [2] 7c ba [2] 6b b1 [2] 70 ff [2] 4d }

  condition:
    any of them
}