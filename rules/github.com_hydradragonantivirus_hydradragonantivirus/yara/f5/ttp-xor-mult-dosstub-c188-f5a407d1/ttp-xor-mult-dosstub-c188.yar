rule TTP_XOR_MULT_DOSStub_c188 {
  strings:
    $key_c188 = { 95 e0 [2] e1 f8 [2] a6 fa [2] e1 eb [2] af e7 [2] a3 ed [2] b4 e6 [2] af a8 [2] 92 }

  condition:
    any of them
}