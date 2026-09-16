rule TTP_XOR_MULT_DOSStub_9681 {
  strings:
    $key_9681 = { c2 e9 [2] b6 f1 [2] f1 f3 [2] b6 e2 [2] f8 ee [2] f4 e4 [2] e3 ef [2] f8 a1 [2] c5 }

  condition:
    any of them
}