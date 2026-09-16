rule TTP_XOR_MULT_DOSStub_c19b {
  strings:
    $key_c19b = { 95 f3 [2] e1 eb [2] a6 e9 [2] e1 f8 [2] af f4 [2] a3 fe [2] b4 f5 [2] af bb [2] 92 }

  condition:
    any of them
}