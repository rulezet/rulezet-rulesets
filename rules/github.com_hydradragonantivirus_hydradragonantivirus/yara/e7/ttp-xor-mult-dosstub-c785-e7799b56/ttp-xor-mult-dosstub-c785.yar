rule TTP_XOR_MULT_DOSStub_c785 {
  strings:
    $key_c785 = { 93 ed [2] e7 f5 [2] a0 f7 [2] e7 e6 [2] a9 ea [2] a5 e0 [2] b2 eb [2] a9 a5 [2] 94 }

  condition:
    any of them
}