rule TTP_XOR_MULT_DOSStub_9c83 {
  strings:
    $key_9c83 = { c8 eb [2] bc f3 [2] fb f1 [2] bc e0 [2] f2 ec [2] fe e6 [2] e9 ed [2] f2 a3 [2] cf }

  condition:
    any of them
}