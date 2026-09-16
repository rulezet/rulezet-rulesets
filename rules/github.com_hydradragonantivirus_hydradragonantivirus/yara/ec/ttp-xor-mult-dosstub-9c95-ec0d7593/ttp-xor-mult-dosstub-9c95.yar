rule TTP_XOR_MULT_DOSStub_9c95 {
  strings:
    $key_9c95 = { c8 fd [2] bc e5 [2] fb e7 [2] bc f6 [2] f2 fa [2] fe f0 [2] e9 fb [2] f2 b5 [2] cf }

  condition:
    any of them
}