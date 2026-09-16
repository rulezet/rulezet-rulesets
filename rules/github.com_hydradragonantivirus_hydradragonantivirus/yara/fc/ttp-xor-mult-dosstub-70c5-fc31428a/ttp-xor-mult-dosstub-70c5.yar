rule TTP_XOR_MULT_DOSStub_70c5 {
  strings:
    $key_70c5 = { 24 ad [2] 50 b5 [2] 17 b7 [2] 50 a6 [2] 1e aa [2] 12 a0 [2] 05 ab [2] 1e e5 [2] 23 }

  condition:
    any of them
}