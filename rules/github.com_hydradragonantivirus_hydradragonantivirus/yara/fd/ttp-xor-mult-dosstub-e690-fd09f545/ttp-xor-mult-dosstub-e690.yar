rule TTP_XOR_MULT_DOSStub_e690 {
  strings:
    $key_e690 = { b2 f8 [2] c6 e0 [2] 81 e2 [2] c6 f3 [2] 88 ff [2] 84 f5 [2] 93 fe [2] 88 b0 [2] b5 }

  condition:
    any of them
}