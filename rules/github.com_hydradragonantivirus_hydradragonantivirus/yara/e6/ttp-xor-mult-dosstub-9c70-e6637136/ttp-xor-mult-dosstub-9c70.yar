rule TTP_XOR_MULT_DOSStub_9c70 {
  strings:
    $key_9c70 = { c8 18 [2] bc 00 [2] fb 02 [2] bc 13 [2] f2 1f [2] fe 15 [2] e9 1e [2] f2 50 [2] cf }

  condition:
    any of them
}