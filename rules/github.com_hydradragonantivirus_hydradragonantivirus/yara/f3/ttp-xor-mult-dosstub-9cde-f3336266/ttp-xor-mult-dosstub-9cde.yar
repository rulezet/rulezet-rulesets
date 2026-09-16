rule TTP_XOR_MULT_DOSStub_9cde {
  strings:
    $key_9cde = { c8 b6 [2] bc ae [2] fb ac [2] bc bd [2] f2 b1 [2] fe bb [2] e9 b0 [2] f2 fe [2] cf }

  condition:
    any of them
}