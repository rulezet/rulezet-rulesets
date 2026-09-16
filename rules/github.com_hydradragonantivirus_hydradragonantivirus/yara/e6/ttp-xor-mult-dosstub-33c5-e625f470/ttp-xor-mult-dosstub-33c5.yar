rule TTP_XOR_MULT_DOSStub_33c5 {
  strings:
    $key_33c5 = { 67 ad [2] 13 b5 [2] 54 b7 [2] 13 a6 [2] 5d aa [2] 51 a0 [2] 46 ab [2] 5d e5 [2] 60 }

  condition:
    any of them
}