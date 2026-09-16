rule TTP_XOR_MULT_DOSStub_9a81 {
  strings:
    $key_9a81 = { ce e9 [2] ba f1 [2] fd f3 [2] ba e2 [2] f4 ee [2] f8 e4 [2] ef ef [2] f4 a1 [2] c9 }

  condition:
    any of them
}