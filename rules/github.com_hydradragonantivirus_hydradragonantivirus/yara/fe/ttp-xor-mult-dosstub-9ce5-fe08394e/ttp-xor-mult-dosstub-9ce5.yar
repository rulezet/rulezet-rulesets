rule TTP_XOR_MULT_DOSStub_9ce5 {
  strings:
    $key_9ce5 = { c8 8d [2] bc 95 [2] fb 97 [2] bc 86 [2] f2 8a [2] fe 80 [2] e9 8b [2] f2 c5 [2] cf }

  condition:
    any of them
}