rule TTP_XOR_MULT_DOSStub_76c8 {
  strings:
    $key_76c8 = { 22 a0 [2] 56 b8 [2] 11 ba [2] 56 ab [2] 18 a7 [2] 14 ad [2] 03 a6 [2] 18 e8 [2] 25 }

  condition:
    any of them
}