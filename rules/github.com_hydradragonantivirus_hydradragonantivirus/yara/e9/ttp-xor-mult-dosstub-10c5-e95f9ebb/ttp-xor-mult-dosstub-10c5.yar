rule TTP_XOR_MULT_DOSStub_10c5 {
  strings:
    $key_10c5 = { 44 ad [2] 30 b5 [2] 77 b7 [2] 30 a6 [2] 7e aa [2] 72 a0 [2] 65 ab [2] 7e e5 [2] 43 }

  condition:
    any of them
}