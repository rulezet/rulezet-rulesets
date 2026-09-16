rule TTP_XOR_MULT_DOSStub_02c7 {
  strings:
    $key_02c7 = { 56 af [2] 22 b7 [2] 65 b5 [2] 22 a4 [2] 6c a8 [2] 60 a2 [2] 77 a9 [2] 6c e7 [2] 51 }

  condition:
    any of them
}