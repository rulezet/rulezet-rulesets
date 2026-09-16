rule TTP_XOR_MULT_DOSStub_d585 {
  strings:
    $key_d585 = { 81 ed [2] f5 f5 [2] b2 f7 [2] f5 e6 [2] bb ea [2] b7 e0 [2] a0 eb [2] bb a5 [2] 86 }

  condition:
    any of them
}