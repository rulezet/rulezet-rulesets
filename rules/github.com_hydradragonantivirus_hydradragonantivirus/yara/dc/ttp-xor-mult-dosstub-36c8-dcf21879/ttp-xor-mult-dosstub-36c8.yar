rule TTP_XOR_MULT_DOSStub_36c8 {
  strings:
    $key_36c8 = { 62 a0 [2] 16 b8 [2] 51 ba [2] 16 ab [2] 58 a7 [2] 54 ad [2] 43 a6 [2] 58 e8 [2] 65 }

  condition:
    any of them
}