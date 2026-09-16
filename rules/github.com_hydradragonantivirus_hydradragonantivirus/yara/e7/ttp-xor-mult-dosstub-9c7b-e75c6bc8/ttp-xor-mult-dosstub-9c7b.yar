rule TTP_XOR_MULT_DOSStub_9c7b {
  strings:
    $key_9c7b = { c8 13 [2] bc 0b [2] fb 09 [2] bc 18 [2] f2 14 [2] fe 1e [2] e9 15 [2] f2 5b [2] cf }

  condition:
    any of them
}