rule TTP_XOR_MULT_DOSStub_31c5 {
  strings:
    $key_31c5 = { 65 ad [2] 11 b5 [2] 56 b7 [2] 11 a6 [2] 5f aa [2] 53 a0 [2] 44 ab [2] 5f e5 [2] 62 }

  condition:
    any of them
}