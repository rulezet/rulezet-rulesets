rule TTP_XOR_MULT_DOSStub_9c18 {
  strings:
    $key_9c18 = { c8 70 [2] bc 68 [2] fb 6a [2] bc 7b [2] f2 77 [2] fe 7d [2] e9 76 [2] f2 38 [2] cf }

  condition:
    any of them
}