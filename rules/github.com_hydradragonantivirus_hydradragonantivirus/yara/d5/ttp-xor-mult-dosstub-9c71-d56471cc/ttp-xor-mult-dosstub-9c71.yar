rule TTP_XOR_MULT_DOSStub_9c71 {
  strings:
    $key_9c71 = { c8 19 [2] bc 01 [2] fb 03 [2] bc 12 [2] f2 1e [2] fe 14 [2] e9 1f [2] f2 51 [2] cf }

  condition:
    any of them
}