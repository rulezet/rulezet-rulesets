rule TTP_XOR_MULT_DOSStub_9ab2 {
  strings:
    $key_9ab2 = { ce da [2] ba c2 [2] fd c0 [2] ba d1 [2] f4 dd [2] f8 d7 [2] ef dc [2] f4 92 [2] c9 }

  condition:
    any of them
}