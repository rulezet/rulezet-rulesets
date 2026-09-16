rule TTP_XOR_MULT_DOSStub_b785 {
  strings:
    $key_b785 = { e3 ed [2] 97 f5 [2] d0 f7 [2] 97 e6 [2] d9 ea [2] d5 e0 [2] c2 eb [2] d9 a5 [2] e4 }

  condition:
    any of them
}