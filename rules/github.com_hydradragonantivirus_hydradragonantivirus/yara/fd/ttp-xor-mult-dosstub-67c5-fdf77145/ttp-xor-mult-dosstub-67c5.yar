rule TTP_XOR_MULT_DOSStub_67c5 {
  strings:
    $key_67c5 = { 33 ad [2] 47 b5 [2] 00 b7 [2] 47 a6 [2] 09 aa [2] 05 a0 [2] 12 ab [2] 09 e5 [2] 34 }

  condition:
    any of them
}