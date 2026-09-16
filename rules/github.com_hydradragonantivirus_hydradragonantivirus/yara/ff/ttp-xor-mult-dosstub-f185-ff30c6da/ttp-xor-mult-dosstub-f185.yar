rule TTP_XOR_MULT_DOSStub_f185 {
  strings:
    $key_f185 = { a5 ed [2] d1 f5 [2] 96 f7 [2] d1 e6 [2] 9f ea [2] 93 e0 [2] 84 eb [2] 9f a5 [2] a2 }

  condition:
    any of them
}