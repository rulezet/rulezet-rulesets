rule TTP_XOR_MULT_DOSStub_8c6a {
  strings:
    $key_8c6a = { d8 02 [2] ac 1a [2] eb 18 [2] ac 09 [2] e2 05 [2] ee 0f [2] f9 04 [2] e2 4a [2] df }

  condition:
    any of them
}