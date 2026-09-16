rule TTP_XOR_MULT_DOSStub_01c3 {
  strings:
    $key_01c3 = { 55 ab [2] 21 b3 [2] 66 b1 [2] 21 a0 [2] 6f ac [2] 63 a6 [2] 74 ad [2] 6f e3 [2] 52 }

  condition:
    any of them
}