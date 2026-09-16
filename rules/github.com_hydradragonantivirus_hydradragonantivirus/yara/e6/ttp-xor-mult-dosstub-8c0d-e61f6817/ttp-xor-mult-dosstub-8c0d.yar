rule TTP_XOR_MULT_DOSStub_8c0d {
  strings:
    $key_8c0d = { d8 65 [2] ac 7d [2] eb 7f [2] ac 6e [2] e2 62 [2] ee 68 [2] f9 63 [2] e2 2d [2] df }

  condition:
    any of them
}