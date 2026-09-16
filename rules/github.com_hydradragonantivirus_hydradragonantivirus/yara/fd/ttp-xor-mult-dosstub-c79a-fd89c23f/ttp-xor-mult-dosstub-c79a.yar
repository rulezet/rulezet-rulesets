rule TTP_XOR_MULT_DOSStub_c79a {
  strings:
    $key_c79a = { 93 f2 [2] e7 ea [2] a0 e8 [2] e7 f9 [2] a9 f5 [2] a5 ff [2] b2 f4 [2] a9 ba [2] 94 }

  condition:
    any of them
}