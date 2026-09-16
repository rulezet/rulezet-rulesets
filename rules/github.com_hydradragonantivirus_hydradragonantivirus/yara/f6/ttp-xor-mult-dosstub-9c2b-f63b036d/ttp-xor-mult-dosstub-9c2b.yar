rule TTP_XOR_MULT_DOSStub_9c2b {
  strings:
    $key_9c2b = { c8 43 [2] bc 5b [2] fb 59 [2] bc 48 [2] f2 44 [2] fe 4e [2] e9 45 [2] f2 0b [2] cf }

  condition:
    any of them
}