rule TTP_XOR_MULT_DOSStub_8963 {
  strings:
    $key_8963 = { dd 0b [2] a9 13 [2] ee 11 [2] a9 00 [2] e7 0c [2] eb 06 [2] fc 0d [2] e7 43 [2] da }

  condition:
    any of them
}