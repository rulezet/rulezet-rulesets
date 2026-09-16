rule TTP_XOR_MULT_DOSStub_9c12 {
  strings:
    $key_9c12 = { c8 7a [2] bc 62 [2] fb 60 [2] bc 71 [2] f2 7d [2] fe 77 [2] e9 7c [2] f2 32 [2] cf }

  condition:
    any of them
}