rule TTP_XOR_MULT_DOSStub_e497 {
  strings:
    $key_e497 = { b0 ff [2] c4 e7 [2] 83 e5 [2] c4 f4 [2] 8a f8 [2] 86 f2 [2] 91 f9 [2] 8a b7 [2] b7 }

  condition:
    any of them
}