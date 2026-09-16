rule TTP_XOR_MULT_DOSStub_76c7 {
  strings:
    $key_76c7 = { 22 af [2] 56 b7 [2] 11 b5 [2] 56 a4 [2] 18 a8 [2] 14 a2 [2] 03 a9 [2] 18 e7 [2] 25 }

  condition:
    any of them
}