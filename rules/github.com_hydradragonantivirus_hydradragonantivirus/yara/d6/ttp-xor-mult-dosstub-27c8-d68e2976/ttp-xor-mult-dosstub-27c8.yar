rule TTP_XOR_MULT_DOSStub_27c8 {
  strings:
    $key_27c8 = { 73 a0 [2] 07 b8 [2] 40 ba [2] 07 ab [2] 49 a7 [2] 45 ad [2] 52 a6 [2] 49 e8 [2] 74 }

  condition:
    any of them
}