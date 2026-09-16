rule TTP_XOR_MULT_DOSStub_9a97 {
  strings:
    $key_9a97 = { ce ff [2] ba e7 [2] fd e5 [2] ba f4 [2] f4 f8 [2] f8 f2 [2] ef f9 [2] f4 b7 [2] c9 }

  condition:
    any of them
}