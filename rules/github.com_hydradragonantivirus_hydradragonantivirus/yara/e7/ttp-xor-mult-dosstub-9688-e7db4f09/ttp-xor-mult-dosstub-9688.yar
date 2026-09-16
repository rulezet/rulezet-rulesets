rule TTP_XOR_MULT_DOSStub_9688 {
  strings:
    $key_9688 = { c2 e0 [2] b6 f8 [2] f1 fa [2] b6 eb [2] f8 e7 [2] f4 ed [2] e3 e6 [2] f8 a8 [2] c5 }

  condition:
    any of them
}