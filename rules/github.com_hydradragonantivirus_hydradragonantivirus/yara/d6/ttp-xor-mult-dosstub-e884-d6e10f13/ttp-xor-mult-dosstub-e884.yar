rule TTP_XOR_MULT_DOSStub_e884 {
  strings:
    $key_e884 = { bc ec [2] c8 f4 [2] 8f f6 [2] c8 e7 [2] 86 eb [2] 8a e1 [2] 9d ea [2] 86 a4 [2] bb }

  condition:
    any of them
}