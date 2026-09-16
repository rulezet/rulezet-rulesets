rule TTP_XOR_MULT_DOSStub_9c34 {
  strings:
    $key_9c34 = { c8 5c [2] bc 44 [2] fb 46 [2] bc 57 [2] f2 5b [2] fe 51 [2] e9 5a [2] f2 14 [2] cf }

  condition:
    any of them
}