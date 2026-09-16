rule TTP_XOR_MULT_DOSStub_41c3 {
  strings:
    $key_41c3 = { 15 ab [2] 61 b3 [2] 26 b1 [2] 61 a0 [2] 2f ac [2] 23 a6 [2] 34 ad [2] 2f e3 [2] 12 }

  condition:
    any of them
}