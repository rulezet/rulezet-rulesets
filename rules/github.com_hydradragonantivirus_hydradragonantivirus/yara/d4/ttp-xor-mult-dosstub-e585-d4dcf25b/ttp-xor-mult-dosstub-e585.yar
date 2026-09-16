rule TTP_XOR_MULT_DOSStub_e585 {
  strings:
    $key_e585 = { b1 ed [2] c5 f5 [2] 82 f7 [2] c5 e6 [2] 8b ea [2] 87 e0 [2] 90 eb [2] 8b a5 [2] b6 }

  condition:
    any of them
}