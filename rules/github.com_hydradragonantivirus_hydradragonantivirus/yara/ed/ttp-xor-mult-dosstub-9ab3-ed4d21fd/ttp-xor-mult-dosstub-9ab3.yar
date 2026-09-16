rule TTP_XOR_MULT_DOSStub_9ab3 {
  strings:
    $key_9ab3 = { ce db [2] ba c3 [2] fd c1 [2] ba d0 [2] f4 dc [2] f8 d6 [2] ef dd [2] f4 93 [2] c9 }

  condition:
    any of them
}