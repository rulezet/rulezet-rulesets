rule TTP_XOR_MULT_DOSStub_9ca6 {
  strings:
    $key_9ca6 = { c8 ce [2] bc d6 [2] fb d4 [2] bc c5 [2] f2 c9 [2] fe c3 [2] e9 c8 [2] f2 86 [2] cf }

  condition:
    any of them
}