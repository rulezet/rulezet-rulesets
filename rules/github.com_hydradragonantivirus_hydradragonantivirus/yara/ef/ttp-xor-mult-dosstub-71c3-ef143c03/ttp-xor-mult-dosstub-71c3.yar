rule TTP_XOR_MULT_DOSStub_71c3 {
  strings:
    $key_71c3 = { 25 ab [2] 51 b3 [2] 16 b1 [2] 51 a0 [2] 1f ac [2] 13 a6 [2] 04 ad [2] 1f e3 [2] 22 }

  condition:
    any of them
}