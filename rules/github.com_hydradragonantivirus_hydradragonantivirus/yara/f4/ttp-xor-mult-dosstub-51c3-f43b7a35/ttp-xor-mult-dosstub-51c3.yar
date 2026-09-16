rule TTP_XOR_MULT_DOSStub_51c3 {
  strings:
    $key_51c3 = { 05 ab [2] 71 b3 [2] 36 b1 [2] 71 a0 [2] 3f ac [2] 33 a6 [2] 24 ad [2] 3f e3 [2] 02 }

  condition:
    any of them
}