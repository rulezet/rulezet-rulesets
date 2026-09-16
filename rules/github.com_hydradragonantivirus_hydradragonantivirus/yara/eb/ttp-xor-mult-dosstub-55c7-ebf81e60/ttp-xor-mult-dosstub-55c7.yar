rule TTP_XOR_MULT_DOSStub_55c7 {
  strings:
    $key_55c7 = { 01 af [2] 75 b7 [2] 32 b5 [2] 75 a4 [2] 3b a8 [2] 37 a2 [2] 20 a9 [2] 3b e7 [2] 06 }

  condition:
    any of them
}