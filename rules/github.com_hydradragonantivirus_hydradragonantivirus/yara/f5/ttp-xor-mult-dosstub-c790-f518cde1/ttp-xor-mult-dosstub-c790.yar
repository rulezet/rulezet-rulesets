rule TTP_XOR_MULT_DOSStub_c790 {
  strings:
    $key_c790 = { 93 f8 [2] e7 e0 [2] a0 e2 [2] e7 f3 [2] a9 ff [2] a5 f5 [2] b2 fe [2] a9 b0 [2] 94 }

  condition:
    any of them
}