rule TTP_XOR_MULT_DOSStub_e597 {
  strings:
    $key_e597 = { b1 ff [2] c5 e7 [2] 82 e5 [2] c5 f4 [2] 8b f8 [2] 87 f2 [2] 90 f9 [2] 8b b7 [2] b6 }

  condition:
    any of them
}