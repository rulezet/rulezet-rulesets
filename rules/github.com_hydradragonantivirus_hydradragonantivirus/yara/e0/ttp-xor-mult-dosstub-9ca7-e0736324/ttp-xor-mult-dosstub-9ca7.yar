rule TTP_XOR_MULT_DOSStub_9ca7 {
  strings:
    $key_9ca7 = { c8 cf [2] bc d7 [2] fb d5 [2] bc c4 [2] f2 c8 [2] fe c2 [2] e9 c9 [2] f2 87 [2] cf }

  condition:
    any of them
}