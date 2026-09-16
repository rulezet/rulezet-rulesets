rule TTP_XOR_MULT_DOSStub_c49a {
  strings:
    $key_c49a = { 90 f2 [2] e4 ea [2] a3 e8 [2] e4 f9 [2] aa f5 [2] a6 ff [2] b1 f4 [2] aa ba [2] 97 }

  condition:
    any of them
}