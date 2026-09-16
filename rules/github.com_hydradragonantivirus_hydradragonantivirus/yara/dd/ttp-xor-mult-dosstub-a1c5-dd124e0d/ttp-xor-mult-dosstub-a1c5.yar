rule TTP_XOR_MULT_DOSStub_a1c5 {
  strings:
    $key_a1c5 = { f5 ad [2] 81 b5 [2] c6 b7 [2] 81 a6 [2] cf aa [2] c3 a0 [2] d4 ab [2] cf e5 [2] f2 }

  condition:
    any of them
}