rule TTP_XOR_MULT_DOSStub_8ceb {
  strings:
    $key_8ceb = { d8 83 [2] ac 9b [2] eb 99 [2] ac 88 [2] e2 84 [2] ee 8e [2] f9 85 [2] e2 cb [2] df }

  condition:
    any of them
}