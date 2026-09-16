rule TTP_XOR_MULT_DOSStub_9caf {
  strings:
    $key_9caf = { c8 c7 [2] bc df [2] fb dd [2] bc cc [2] f2 c0 [2] fe ca [2] e9 c1 [2] f2 8f [2] cf }

  condition:
    any of them
}