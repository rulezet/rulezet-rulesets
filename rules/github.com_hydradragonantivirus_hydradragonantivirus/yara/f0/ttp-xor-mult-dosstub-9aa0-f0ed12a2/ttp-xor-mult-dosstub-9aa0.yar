rule TTP_XOR_MULT_DOSStub_9aa0 {
  strings:
    $key_9aa0 = { ce c8 [2] ba d0 [2] fd d2 [2] ba c3 [2] f4 cf [2] f8 c5 [2] ef ce [2] f4 80 [2] c9 }

  condition:
    any of them
}