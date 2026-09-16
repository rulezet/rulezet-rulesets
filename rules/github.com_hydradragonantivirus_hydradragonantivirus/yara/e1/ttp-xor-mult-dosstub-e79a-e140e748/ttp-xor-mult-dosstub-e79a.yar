rule TTP_XOR_MULT_DOSStub_e79a {
  strings:
    $key_e79a = { b3 f2 [2] c7 ea [2] 80 e8 [2] c7 f9 [2] 89 f5 [2] 85 ff [2] 92 f4 [2] 89 ba [2] b4 }

  condition:
    any of them
}