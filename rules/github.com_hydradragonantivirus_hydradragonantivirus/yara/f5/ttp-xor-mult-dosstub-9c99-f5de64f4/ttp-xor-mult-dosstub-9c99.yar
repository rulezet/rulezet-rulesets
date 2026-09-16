rule TTP_XOR_MULT_DOSStub_9c99 {
  strings:
    $key_9c99 = { c8 f1 [2] bc e9 [2] fb eb [2] bc fa [2] f2 f6 [2] fe fc [2] e9 f7 [2] f2 b9 [2] cf }

  condition:
    any of them
}