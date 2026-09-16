rule TTP_XOR_MULT_DOSStub_9ca1 {
  strings:
    $key_9ca1 = { c8 c9 [2] bc d1 [2] fb d3 [2] bc c2 [2] f2 ce [2] fe c4 [2] e9 cf [2] f2 81 [2] cf }

  condition:
    any of them
}