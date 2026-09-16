rule TTP_XOR_MULT_DOSStub_9a87 {
  strings:
    $key_9a87 = { ce ef [2] ba f7 [2] fd f5 [2] ba e4 [2] f4 e8 [2] f8 e2 [2] ef e9 [2] f4 a7 [2] c9 }

  condition:
    any of them
}