rule TTP_XOR_MULT_DOSStub_e697 {
  strings:
    $key_e697 = { b2 ff [2] c6 e7 [2] 81 e5 [2] c6 f4 [2] 88 f8 [2] 84 f2 [2] 93 f9 [2] 88 b7 [2] b5 }

  condition:
    any of them
}