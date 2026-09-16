rule TTP_XOR_MULT_DOSStub_c19a {
  strings:
    $key_c19a = { 95 f2 [2] e1 ea [2] a6 e8 [2] e1 f9 [2] af f5 [2] a3 ff [2] b4 f4 [2] af ba [2] 92 }

  condition:
    any of them
}