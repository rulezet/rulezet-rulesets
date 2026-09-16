rule TTP_XOR_MULT_DOSStub_9c55 {
  strings:
    $key_9c55 = { c8 3d [2] bc 25 [2] fb 27 [2] bc 36 [2] f2 3a [2] fe 30 [2] e9 3b [2] f2 75 [2] cf }

  condition:
    any of them
}