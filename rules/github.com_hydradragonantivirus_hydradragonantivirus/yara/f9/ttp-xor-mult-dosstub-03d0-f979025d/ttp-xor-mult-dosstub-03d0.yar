rule TTP_XOR_MULT_DOSStub_03d0 {
  strings:
    $key_03d0 = { 57 b8 [2] 23 a0 [2] 64 a2 [2] 23 b3 [2] 6d bf [2] 61 b5 [2] 76 be [2] 6d f0 [2] 50 }

  condition:
    any of them
}