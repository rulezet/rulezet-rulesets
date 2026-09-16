rule TTP_XOR_MULT_DOSStub_73c5 {
  strings:
    $key_73c5 = { 27 ad [2] 53 b5 [2] 14 b7 [2] 53 a6 [2] 1d aa [2] 11 a0 [2] 06 ab [2] 1d e5 [2] 20 }

  condition:
    any of them
}