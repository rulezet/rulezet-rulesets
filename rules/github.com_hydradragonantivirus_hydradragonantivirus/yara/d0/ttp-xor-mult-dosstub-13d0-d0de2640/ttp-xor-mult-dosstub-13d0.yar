rule TTP_XOR_MULT_DOSStub_13d0 {
  strings:
    $key_13d0 = { 47 b8 [2] 33 a0 [2] 74 a2 [2] 33 b3 [2] 7d bf [2] 71 b5 [2] 66 be [2] 7d f0 [2] 40 }

  condition:
    any of them
}