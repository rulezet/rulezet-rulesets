rule TTP_XOR_MULT_DOSStub_e8d1 {
  strings:
    $key_e8d1 = { bc b9 [2] c8 a1 [2] 8f a3 [2] c8 b2 [2] 86 be [2] 8a b4 [2] 9d bf [2] 86 f1 [2] bb }

  condition:
    any of them
}