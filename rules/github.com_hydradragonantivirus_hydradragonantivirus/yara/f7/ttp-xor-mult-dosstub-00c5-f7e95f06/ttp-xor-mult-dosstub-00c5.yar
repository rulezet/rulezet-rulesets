rule TTP_XOR_MULT_DOSStub_00c5 {
  strings:
    $key_00c5 = { 54 ad [2] 20 b5 [2] 67 b7 [2] 20 a6 [2] 6e aa [2] 62 a0 [2] 75 ab [2] 6e e5 [2] 53 }

  condition:
    any of them
}