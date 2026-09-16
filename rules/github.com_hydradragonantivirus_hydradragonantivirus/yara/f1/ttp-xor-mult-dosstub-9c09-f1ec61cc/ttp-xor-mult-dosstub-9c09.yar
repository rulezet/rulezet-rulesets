rule TTP_XOR_MULT_DOSStub_9c09 {
  strings:
    $key_9c09 = { c8 61 [2] bc 79 [2] fb 7b [2] bc 6a [2] f2 66 [2] fe 6c [2] e9 67 [2] f2 29 [2] cf }

  condition:
    any of them
}