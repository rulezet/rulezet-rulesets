rule TTP_XOR_MULT_DOSStub_f5c3 {
  strings:
    $key_f5c3 = { a1 ab [2] d5 b3 [2] 92 b1 [2] d5 a0 [2] 9b ac [2] 97 a6 [2] 80 ad [2] 9b e3 [2] a6 }

  condition:
    any of them
}