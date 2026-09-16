rule TTP_XOR_MULT_DOSStub_e1c7 {
  strings:
    $key_e1c7 = { b5 af [2] c1 b7 [2] 86 b5 [2] c1 a4 [2] 8f a8 [2] 83 a2 [2] 94 a9 [2] 8f e7 [2] b2 }

  condition:
    any of them
}