rule TTP_XOR_MULT_DOSStub_fb84 {
  strings:
    $key_fb84 = { af ec [2] db f4 [2] 9c f6 [2] db e7 [2] 95 eb [2] 99 e1 [2] 8e ea [2] 95 a4 [2] a8 }

  condition:
    any of them
}