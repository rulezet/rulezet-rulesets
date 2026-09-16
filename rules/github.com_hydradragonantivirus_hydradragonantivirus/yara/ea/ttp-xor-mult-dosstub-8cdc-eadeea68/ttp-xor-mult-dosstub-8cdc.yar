rule TTP_XOR_MULT_DOSStub_8cdc {
  strings:
    $key_8cdc = { d8 b4 [2] ac ac [2] eb ae [2] ac bf [2] e2 b3 [2] ee b9 [2] f9 b2 [2] e2 fc [2] df }

  condition:
    any of them
}