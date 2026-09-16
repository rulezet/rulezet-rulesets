rule TTP_XOR_MULT_DOSStub_9686 {
  strings:
    $key_9686 = { c2 ee [2] b6 f6 [2] f1 f4 [2] b6 e5 [2] f8 e9 [2] f4 e3 [2] e3 e8 [2] f8 a6 [2] c5 }

  condition:
    any of them
}