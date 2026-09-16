rule TTP_XOR_MULT_DOSStub_8f89 {
  strings:
    $key_8f89 = { db e1 [2] af f9 [2] e8 fb [2] af ea [2] e1 e6 [2] ed ec [2] fa e7 [2] e1 a9 [2] dc }

  condition:
    any of them
}