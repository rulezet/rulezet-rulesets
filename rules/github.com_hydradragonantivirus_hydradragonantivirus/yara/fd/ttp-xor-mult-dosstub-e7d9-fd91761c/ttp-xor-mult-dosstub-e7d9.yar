rule TTP_XOR_MULT_DOSStub_e7d9 {
  strings:
    $key_e7d9 = { b3 b1 [2] c7 a9 [2] 80 ab [2] c7 ba [2] 89 b6 [2] 85 bc [2] 92 b7 [2] 89 f9 [2] b4 }

  condition:
    any of them
}