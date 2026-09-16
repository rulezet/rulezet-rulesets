rule TTP_XOR_MULT_DOSStub_9c33 {
  strings:
    $key_9c33 = { c8 5b [2] bc 43 [2] fb 41 [2] bc 50 [2] f2 5c [2] fe 56 [2] e9 5d [2] f2 13 [2] cf }

  condition:
    any of them
}