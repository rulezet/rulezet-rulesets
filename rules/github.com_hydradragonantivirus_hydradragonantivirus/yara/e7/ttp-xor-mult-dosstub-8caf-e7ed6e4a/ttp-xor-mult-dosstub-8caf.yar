rule TTP_XOR_MULT_DOSStub_8caf {
  strings:
    $key_8caf = { d8 c7 [2] ac df [2] eb dd [2] ac cc [2] e2 c0 [2] ee ca [2] f9 c1 [2] e2 8f [2] df }

  condition:
    any of them
}