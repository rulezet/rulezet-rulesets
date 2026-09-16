rule TTP_XOR_MULT_DOSStub_9288 {
  strings:
    $key_9288 = { c6 e0 [2] b2 f8 [2] f5 fa [2] b2 eb [2] fc e7 [2] f0 ed [2] e7 e6 [2] fc a8 [2] c1 }

  condition:
    any of them
}