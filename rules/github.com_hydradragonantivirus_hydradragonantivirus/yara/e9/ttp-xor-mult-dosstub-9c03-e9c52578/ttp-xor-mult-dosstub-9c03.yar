rule TTP_XOR_MULT_DOSStub_9c03 {
  strings:
    $key_9c03 = { c8 6b [2] bc 73 [2] fb 71 [2] bc 60 [2] f2 6c [2] fe 66 [2] e9 6d [2] f2 23 [2] cf }

  condition:
    any of them
}