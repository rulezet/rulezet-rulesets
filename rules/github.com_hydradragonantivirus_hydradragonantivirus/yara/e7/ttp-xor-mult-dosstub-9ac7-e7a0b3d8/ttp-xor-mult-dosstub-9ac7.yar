rule TTP_XOR_MULT_DOSStub_9ac7 {
  strings:
    $key_9ac7 = { ce af [2] ba b7 [2] fd b5 [2] ba a4 [2] f4 a8 [2] f8 a2 [2] ef a9 [2] f4 e7 [2] c9 }

  condition:
    any of them
}