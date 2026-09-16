rule TTP_XOR_MULT_DOSStub_21c5 {
  strings:
    $key_21c5 = { 75 ad [2] 01 b5 [2] 46 b7 [2] 01 a6 [2] 4f aa [2] 43 a0 [2] 54 ab [2] 4f e5 [2] 72 }

  condition:
    any of them
}