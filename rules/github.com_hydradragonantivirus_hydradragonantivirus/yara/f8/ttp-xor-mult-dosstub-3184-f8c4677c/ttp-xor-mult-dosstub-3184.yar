rule TTP_XOR_MULT_DOSStub_3184 {
  strings:
    $key_3184 = { 65 ec [2] 11 f4 [2] 56 f6 [2] 11 e7 [2] 5f eb [2] 53 e1 [2] 44 ea [2] 5f a4 [2] 62 }

  condition:
    any of them
}