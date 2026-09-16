rule TTP_XOR_MULT_DOSStub_46c5 {
  strings:
    $key_46c5 = { 12 ad [2] 66 b5 [2] 21 b7 [2] 66 a6 [2] 28 aa [2] 24 a0 [2] 33 ab [2] 28 e5 [2] 15 }

  condition:
    any of them
}