rule TTP_XOR_MULT_DOSStub_9ccf {
  strings:
    $key_9ccf = { c8 a7 [2] bc bf [2] fb bd [2] bc ac [2] f2 a0 [2] fe aa [2] e9 a1 [2] f2 ef [2] cf }

  condition:
    any of them
}