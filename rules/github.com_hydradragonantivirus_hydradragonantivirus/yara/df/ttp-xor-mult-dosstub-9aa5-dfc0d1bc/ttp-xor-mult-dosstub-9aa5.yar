rule TTP_XOR_MULT_DOSStub_9aa5 {
  strings:
    $key_9aa5 = { ce cd [2] ba d5 [2] fd d7 [2] ba c6 [2] f4 ca [2] f8 c0 [2] ef cb [2] f4 85 [2] c9 }

  condition:
    any of them
}