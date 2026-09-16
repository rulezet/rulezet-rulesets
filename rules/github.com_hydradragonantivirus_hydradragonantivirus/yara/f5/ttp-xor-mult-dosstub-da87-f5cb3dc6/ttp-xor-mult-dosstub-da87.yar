rule TTP_XOR_MULT_DOSStub_da87 {
  strings:
    $key_da87 = { 8e ef [2] fa f7 [2] bd f5 [2] fa e4 [2] b4 e8 [2] b8 e2 [2] af e9 [2] b4 a7 [2] 89 }

  condition:
    any of them
}