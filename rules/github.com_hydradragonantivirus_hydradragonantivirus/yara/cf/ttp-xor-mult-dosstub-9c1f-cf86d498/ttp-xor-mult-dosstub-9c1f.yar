rule TTP_XOR_MULT_DOSStub_9c1f {
  strings:
    $key_9c1f = { c8 77 [2] bc 6f [2] fb 6d [2] bc 7c [2] f2 70 [2] fe 7a [2] e9 71 [2] f2 3f [2] cf }

  condition:
    any of them
}