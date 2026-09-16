rule TTP_XOR_MULT_DOSStub_e790 {
  strings:
    $key_e790 = { b3 f8 [2] c7 e0 [2] 80 e2 [2] c7 f3 [2] 89 ff [2] 85 f5 [2] 92 fe [2] 89 b0 [2] b4 }

  condition:
    any of them
}