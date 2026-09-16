rule TTP_XOR_MULT_DOSStub_9aaa {
  strings:
    $key_9aaa = { ce c2 [2] ba da [2] fd d8 [2] ba c9 [2] f4 c5 [2] f8 cf [2] ef c4 [2] f4 8a [2] c9 }

  condition:
    any of them
}