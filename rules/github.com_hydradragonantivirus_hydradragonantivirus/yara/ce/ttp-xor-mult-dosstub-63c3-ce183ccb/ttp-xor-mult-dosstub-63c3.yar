rule TTP_XOR_MULT_DOSStub_63c3 {
  strings:
    $key_63c3 = { 37 ab [2] 43 b3 [2] 04 b1 [2] 43 a0 [2] 0d ac [2] 01 a6 [2] 16 ad [2] 0d e3 [2] 30 }

  condition:
    any of them
}