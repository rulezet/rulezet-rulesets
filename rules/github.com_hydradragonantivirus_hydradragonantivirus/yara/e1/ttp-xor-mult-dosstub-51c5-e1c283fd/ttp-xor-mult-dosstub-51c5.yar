rule TTP_XOR_MULT_DOSStub_51c5 {
  strings:
    $key_51c5 = { 05 ad [2] 71 b5 [2] 36 b7 [2] 71 a6 [2] 3f aa [2] 33 a0 [2] 24 ab [2] 3f e5 [2] 02 }

  condition:
    any of them
}