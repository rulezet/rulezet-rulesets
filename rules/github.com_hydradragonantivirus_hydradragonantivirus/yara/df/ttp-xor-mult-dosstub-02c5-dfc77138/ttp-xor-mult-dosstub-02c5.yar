rule TTP_XOR_MULT_DOSStub_02c5 {
  strings:
    $key_02c5 = { 56 ad [2] 22 b5 [2] 65 b7 [2] 22 a6 [2] 6c aa [2] 60 a0 [2] 77 ab [2] 6c e5 [2] 51 }

  condition:
    any of them
}