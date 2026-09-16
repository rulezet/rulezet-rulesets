rule TTP_XOR_MULT_DOSStub_9c3d {
  strings:
    $key_9c3d = { c8 55 [2] bc 4d [2] fb 4f [2] bc 5e [2] f2 52 [2] fe 58 [2] e9 53 [2] f2 1d [2] cf }

  condition:
    any of them
}