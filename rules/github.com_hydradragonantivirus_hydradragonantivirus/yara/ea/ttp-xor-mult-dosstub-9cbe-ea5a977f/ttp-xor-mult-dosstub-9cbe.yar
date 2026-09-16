rule TTP_XOR_MULT_DOSStub_9cbe {
  strings:
    $key_9cbe = { c8 d6 [2] bc ce [2] fb cc [2] bc dd [2] f2 d1 [2] fe db [2] e9 d0 [2] f2 9e [2] cf }

  condition:
    any of them
}