rule TTP_XOR_MULT_DOSStub_9c97 {
  strings:
    $key_9c97 = { c8 ff [2] bc e7 [2] fb e5 [2] bc f4 [2] f2 f8 [2] fe f2 [2] e9 f9 [2] f2 b7 [2] cf }

  condition:
    any of them
}