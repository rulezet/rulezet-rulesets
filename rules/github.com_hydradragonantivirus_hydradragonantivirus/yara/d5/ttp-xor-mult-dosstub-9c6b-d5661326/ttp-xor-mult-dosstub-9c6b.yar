rule TTP_XOR_MULT_DOSStub_9c6b {
  strings:
    $key_9c6b = { c8 03 [2] bc 1b [2] fb 19 [2] bc 08 [2] f2 04 [2] fe 0e [2] e9 05 [2] f2 4b [2] cf }

  condition:
    any of them
}