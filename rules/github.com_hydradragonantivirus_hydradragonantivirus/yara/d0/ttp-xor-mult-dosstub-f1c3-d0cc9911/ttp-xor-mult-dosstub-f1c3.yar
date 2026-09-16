rule TTP_XOR_MULT_DOSStub_f1c3 {
  strings:
    $key_f1c3 = { a5 ab [2] d1 b3 [2] 96 b1 [2] d1 a0 [2] 9f ac [2] 93 a6 [2] 84 ad [2] 9f e3 [2] a2 }

  condition:
    any of them
}