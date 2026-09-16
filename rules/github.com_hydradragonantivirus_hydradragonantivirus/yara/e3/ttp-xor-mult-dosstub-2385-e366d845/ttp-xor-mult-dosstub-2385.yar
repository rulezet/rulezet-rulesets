rule TTP_XOR_MULT_DOSStub_2385 {
  strings:
    $key_2385 = { 77 ed [2] 03 f5 [2] 44 f7 [2] 03 e6 [2] 4d ea [2] 41 e0 [2] 56 eb [2] 4d a5 [2] 70 }

  condition:
    any of them
}