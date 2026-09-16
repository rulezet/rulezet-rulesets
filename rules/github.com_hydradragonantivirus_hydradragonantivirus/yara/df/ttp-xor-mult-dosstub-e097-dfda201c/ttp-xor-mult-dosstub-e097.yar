rule TTP_XOR_MULT_DOSStub_e097 {
  strings:
    $key_e097 = { b4 ff [2] c0 e7 [2] 87 e5 [2] c0 f4 [2] 8e f8 [2] 82 f2 [2] 95 f9 [2] 8e b7 [2] b3 }

  condition:
    any of them
}