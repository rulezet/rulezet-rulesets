rule TTP_XOR_MULT_DOSStub_9cdc {
  strings:
    $key_9cdc = { c8 b4 [2] bc ac [2] fb ae [2] bc bf [2] f2 b3 [2] fe b9 [2] e9 b2 [2] f2 fc [2] cf }

  condition:
    any of them
}