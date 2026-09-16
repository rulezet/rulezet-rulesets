rule TTP_XOR_MULT_DOSStub_35c5 {
  strings:
    $key_35c5 = { 61 ad [2] 15 b5 [2] 52 b7 [2] 15 a6 [2] 5b aa [2] 57 a0 [2] 40 ab [2] 5b e5 [2] 66 }

  condition:
    any of them
}