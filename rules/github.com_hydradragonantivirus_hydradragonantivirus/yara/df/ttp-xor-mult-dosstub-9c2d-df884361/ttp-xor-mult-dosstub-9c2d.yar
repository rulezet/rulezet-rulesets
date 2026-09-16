rule TTP_XOR_MULT_DOSStub_9c2d {
  strings:
    $key_9c2d = { c8 45 [2] bc 5d [2] fb 5f [2] bc 4e [2] f2 42 [2] fe 48 [2] e9 43 [2] f2 0d [2] cf }

  condition:
    any of them
}