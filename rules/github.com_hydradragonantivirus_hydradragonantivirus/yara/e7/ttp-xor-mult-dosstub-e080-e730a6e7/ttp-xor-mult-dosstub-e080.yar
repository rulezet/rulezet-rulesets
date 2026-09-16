rule TTP_XOR_MULT_DOSStub_e080 {
  strings:
    $key_e080 = { b4 e8 [2] c0 f0 [2] 87 f2 [2] c0 e3 [2] 8e ef [2] 82 e5 [2] 95 ee [2] 8e a0 [2] b3 }

  condition:
    any of them
}