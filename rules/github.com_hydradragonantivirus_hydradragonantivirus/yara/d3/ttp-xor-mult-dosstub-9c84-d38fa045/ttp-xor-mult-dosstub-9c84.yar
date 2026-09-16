rule TTP_XOR_MULT_DOSStub_9c84 {
  strings:
    $key_9c84 = { c8 ec [2] bc f4 [2] fb f6 [2] bc e7 [2] f2 eb [2] fe e1 [2] e9 ea [2] f2 a4 [2] cf }

  condition:
    any of them
}