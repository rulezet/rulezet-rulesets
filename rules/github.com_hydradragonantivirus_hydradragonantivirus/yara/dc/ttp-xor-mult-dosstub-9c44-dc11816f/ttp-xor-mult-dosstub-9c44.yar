rule TTP_XOR_MULT_DOSStub_9c44 {
  strings:
    $key_9c44 = { c8 2c [2] bc 34 [2] fb 36 [2] bc 27 [2] f2 2b [2] fe 21 [2] e9 2a [2] f2 64 [2] cf }

  condition:
    any of them
}