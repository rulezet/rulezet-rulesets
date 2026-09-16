rule TTP_XOR_MULT_DOSStub_9ce1 {
  strings:
    $key_9ce1 = { c8 89 [2] bc 91 [2] fb 93 [2] bc 82 [2] f2 8e [2] fe 84 [2] e9 8f [2] f2 c1 [2] cf }

  condition:
    any of them
}