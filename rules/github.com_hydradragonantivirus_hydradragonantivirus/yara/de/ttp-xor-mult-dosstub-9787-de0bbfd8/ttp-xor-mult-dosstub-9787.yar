rule TTP_XOR_MULT_DOSStub_9787 {
  strings:
    $key_9787 = { c3 ef [2] b7 f7 [2] f0 f5 [2] b7 e4 [2] f9 e8 [2] f5 e2 [2] e2 e9 [2] f9 a7 [2] c4 }

  condition:
    any of them
}