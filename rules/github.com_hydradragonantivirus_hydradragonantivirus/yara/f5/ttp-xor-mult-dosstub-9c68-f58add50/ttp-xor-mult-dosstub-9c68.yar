rule TTP_XOR_MULT_DOSStub_9c68 {
  strings:
    $key_9c68 = { c8 00 [2] bc 18 [2] fb 1a [2] bc 0b [2] f2 07 [2] fe 0d [2] e9 06 [2] f2 48 [2] cf }

  condition:
    any of them
}