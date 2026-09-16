rule TTP_XOR_MULT_DOSStub_9cc5 {
  strings:
    $key_9cc5 = { c8 ad [2] bc b5 [2] fb b7 [2] bc a6 [2] f2 aa [2] fe a0 [2] e9 ab [2] f2 e5 [2] cf }

  condition:
    any of them
}