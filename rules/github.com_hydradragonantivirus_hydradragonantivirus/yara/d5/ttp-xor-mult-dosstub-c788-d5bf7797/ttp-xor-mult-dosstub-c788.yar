rule TTP_XOR_MULT_DOSStub_c788 {
  strings:
    $key_c788 = { 93 e0 [2] e7 f8 [2] a0 fa [2] e7 eb [2] a9 e7 [2] a5 ed [2] b2 e6 [2] a9 a8 [2] 94 }

  condition:
    any of them
}