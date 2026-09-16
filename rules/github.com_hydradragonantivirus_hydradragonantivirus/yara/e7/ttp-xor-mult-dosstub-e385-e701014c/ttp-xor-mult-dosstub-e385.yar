rule TTP_XOR_MULT_DOSStub_e385 {
  strings:
    $key_e385 = { b7 ed [2] c3 f5 [2] 84 f7 [2] c3 e6 [2] 8d ea [2] 81 e0 [2] 96 eb [2] 8d a5 [2] b0 }

  condition:
    any of them
}