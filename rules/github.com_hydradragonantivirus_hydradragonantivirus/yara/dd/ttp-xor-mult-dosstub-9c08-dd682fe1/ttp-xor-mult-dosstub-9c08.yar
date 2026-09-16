rule TTP_XOR_MULT_DOSStub_9c08 {
  strings:
    $key_9c08 = { c8 60 [2] bc 78 [2] fb 7a [2] bc 6b [2] f2 67 [2] fe 6d [2] e9 66 [2] f2 28 [2] cf }

  condition:
    any of them
}