rule TTP_XOR_MULT_DOSStub_c791 {
  strings:
    $key_c791 = { 93 f9 [2] e7 e1 [2] a0 e3 [2] e7 f2 [2] a9 fe [2] a5 f4 [2] b2 ff [2] a9 b1 [2] 94 }

  condition:
    any of them
}