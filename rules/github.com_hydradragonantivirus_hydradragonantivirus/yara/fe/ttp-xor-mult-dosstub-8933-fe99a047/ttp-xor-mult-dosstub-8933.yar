rule TTP_XOR_MULT_DOSStub_8933 {
  strings:
    $key_8933 = { dd 5b [2] a9 43 [2] ee 41 [2] a9 50 [2] e7 5c [2] eb 56 [2] fc 5d [2] e7 13 [2] da }

  condition:
    any of them
}