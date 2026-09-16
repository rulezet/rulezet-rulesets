rule TTP_XOR_MULT_DOSStub_e69a {
  strings:
    $key_e69a = { b2 f2 [2] c6 ea [2] 81 e8 [2] c6 f9 [2] 88 f5 [2] 84 ff [2] 93 f4 [2] 88 ba [2] b5 }

  condition:
    any of them
}