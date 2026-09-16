rule TTP_XOR_MULT_DOSStub_e39a {
  strings:
    $key_e39a = { b7 f2 [2] c3 ea [2] 84 e8 [2] c3 f9 [2] 8d f5 [2] 81 ff [2] 96 f4 [2] 8d ba [2] b0 }

  condition:
    any of them
}