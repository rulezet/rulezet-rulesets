rule TTP_XOR_MULT_DOSStub_9588 {
  strings:
    $key_9588 = { c1 e0 [2] b5 f8 [2] f2 fa [2] b5 eb [2] fb e7 [2] f7 ed [2] e0 e6 [2] fb a8 [2] c6 }

  condition:
    any of them
}