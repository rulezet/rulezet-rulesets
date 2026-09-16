rule TTP_XOR_MULT_DOSStub_9c05 {
  strings:
    $key_9c05 = { c8 6d [2] bc 75 [2] fb 77 [2] bc 66 [2] f2 6a [2] fe 60 [2] e9 6b [2] f2 25 [2] cf }

  condition:
    any of them
}