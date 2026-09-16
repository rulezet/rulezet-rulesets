rule TTP_XOR_MULT_DOSStub_9c8d {
  strings:
    $key_9c8d = { c8 e5 [2] bc fd [2] fb ff [2] bc ee [2] f2 e2 [2] fe e8 [2] e9 e3 [2] f2 ad [2] cf }

  condition:
    any of them
}