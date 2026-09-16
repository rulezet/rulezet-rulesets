rule TTP_XOR_MULT_DOSStub_9c64 {
  strings:
    $key_9c64 = { c8 0c [2] bc 14 [2] fb 16 [2] bc 07 [2] f2 0b [2] fe 01 [2] e9 0a [2] f2 44 [2] cf }

  condition:
    any of them
}