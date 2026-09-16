rule TTP_XOR_MULT_DOSStub_89ed {
  strings:
    $key_89ed = { dd 85 [2] a9 9d [2] ee 9f [2] a9 8e [2] e7 82 [2] eb 88 [2] fc 83 [2] e7 cd [2] da }

  condition:
    any of them
}