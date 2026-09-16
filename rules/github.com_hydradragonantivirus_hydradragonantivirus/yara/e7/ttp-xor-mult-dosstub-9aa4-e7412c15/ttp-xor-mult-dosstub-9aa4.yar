rule TTP_XOR_MULT_DOSStub_9aa4 {
  strings:
    $key_9aa4 = { ce cc [2] ba d4 [2] fd d6 [2] ba c7 [2] f4 cb [2] f8 c1 [2] ef ca [2] f4 84 [2] c9 }

  condition:
    any of them
}