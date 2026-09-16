rule TTP_XOR_MULT_DOSStub_9c8a {
  strings:
    $key_9c8a = { c8 e2 [2] bc fa [2] fb f8 [2] bc e9 [2] f2 e5 [2] fe ef [2] e9 e4 [2] f2 aa [2] cf }

  condition:
    any of them
}