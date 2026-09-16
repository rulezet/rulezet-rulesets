rule TTP_XOR_MULT_DOSStub_e59a {
  strings:
    $key_e59a = { b1 f2 [2] c5 ea [2] 82 e8 [2] c5 f9 [2] 8b f5 [2] 87 ff [2] 90 f4 [2] 8b ba [2] b6 }

  condition:
    any of them
}