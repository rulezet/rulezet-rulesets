rule TTP_XOR_MULT_DOSStub_9c29 {
  strings:
    $key_9c29 = { c8 41 [2] bc 59 [2] fb 5b [2] bc 4a [2] f2 46 [2] fe 4c [2] e9 47 [2] f2 09 [2] cf }

  condition:
    any of them
}