rule TTP_XOR_MULT_DOSStub_e186 {
  strings:
    $key_e186 = { b5 ee [2] c1 f6 [2] 86 f4 [2] c1 e5 [2] 8f e9 [2] 83 e3 [2] 94 e8 [2] 8f a6 [2] b2 }

  condition:
    any of them
}