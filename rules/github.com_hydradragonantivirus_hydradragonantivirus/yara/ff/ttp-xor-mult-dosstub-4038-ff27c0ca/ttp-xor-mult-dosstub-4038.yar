rule TTP_XOR_MULT_DOSStub_4038 {
  strings:
    $key_4038 = { 14 50 [2] 60 48 [2] 27 4a [2] 60 5b [2] 2e 57 [2] 22 5d [2] 35 56 [2] 2e 18 [2] 13 }

  condition:
    any of them
}