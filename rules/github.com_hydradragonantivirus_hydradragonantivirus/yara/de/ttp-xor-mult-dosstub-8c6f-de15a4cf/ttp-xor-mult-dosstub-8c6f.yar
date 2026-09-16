rule TTP_XOR_MULT_DOSStub_8c6f {
  strings:
    $key_8c6f = { d8 07 [2] ac 1f [2] eb 1d [2] ac 0c [2] e2 00 [2] ee 0a [2] f9 01 [2] e2 4f [2] df }

  condition:
    any of them
}