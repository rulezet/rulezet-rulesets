rule TTP_XOR_MULT_DOSStub_9cc1 {
  strings:
    $key_9cc1 = { c8 a9 [2] bc b1 [2] fb b3 [2] bc a2 [2] f2 ae [2] fe a4 [2] e9 af [2] f2 e1 [2] cf }

  condition:
    any of them
}