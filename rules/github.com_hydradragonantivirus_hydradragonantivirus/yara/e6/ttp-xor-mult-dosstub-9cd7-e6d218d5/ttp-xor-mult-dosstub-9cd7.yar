rule TTP_XOR_MULT_DOSStub_9cd7 {
  strings:
    $key_9cd7 = { c8 bf [2] bc a7 [2] fb a5 [2] bc b4 [2] f2 b8 [2] fe b2 [2] e9 b9 [2] f2 f7 [2] cf }

  condition:
    any of them
}