rule TTP_XOR_MULT_DOSStub_9ceb {
  strings:
    $key_9ceb = { c8 83 [2] bc 9b [2] fb 99 [2] bc 88 [2] f2 84 [2] fe 8e [2] e9 85 [2] f2 cb [2] cf }

  condition:
    any of them
}