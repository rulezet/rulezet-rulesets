rule TTP_XOR_MULT_DOSStub_63c8 {
  strings:
    $key_63c8 = { 37 a0 [2] 43 b8 [2] 04 ba [2] 43 ab [2] 0d a7 [2] 01 ad [2] 16 a6 [2] 0d e8 [2] 30 }

  condition:
    any of them
}