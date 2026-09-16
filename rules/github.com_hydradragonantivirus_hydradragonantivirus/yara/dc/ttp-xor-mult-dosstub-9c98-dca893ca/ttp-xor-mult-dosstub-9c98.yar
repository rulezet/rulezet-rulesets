rule TTP_XOR_MULT_DOSStub_9c98 {
  strings:
    $key_9c98 = { c8 f0 [2] bc e8 [2] fb ea [2] bc fb [2] f2 f7 [2] fe fd [2] e9 f6 [2] f2 b8 [2] cf }

  condition:
    any of them
}