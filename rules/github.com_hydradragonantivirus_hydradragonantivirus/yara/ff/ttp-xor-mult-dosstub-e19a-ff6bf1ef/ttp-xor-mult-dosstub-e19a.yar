rule TTP_XOR_MULT_DOSStub_e19a {
  strings:
    $key_e19a = { b5 f2 [2] c1 ea [2] 86 e8 [2] c1 f9 [2] 8f f5 [2] 83 ff [2] 94 f4 [2] 8f ba [2] b2 }

  condition:
    any of them
}