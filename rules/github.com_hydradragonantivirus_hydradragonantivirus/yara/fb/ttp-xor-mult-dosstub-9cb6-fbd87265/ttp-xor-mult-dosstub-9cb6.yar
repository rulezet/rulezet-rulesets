rule TTP_XOR_MULT_DOSStub_9cb6 {
  strings:
    $key_9cb6 = { c8 de [2] bc c6 [2] fb c4 [2] bc d5 [2] f2 d9 [2] fe d3 [2] e9 d8 [2] f2 96 [2] cf }

  condition:
    any of them
}