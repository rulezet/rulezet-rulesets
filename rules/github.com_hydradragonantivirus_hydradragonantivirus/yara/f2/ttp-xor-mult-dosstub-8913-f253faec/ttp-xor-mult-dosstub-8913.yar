rule TTP_XOR_MULT_DOSStub_8913 {
  strings:
    $key_8913 = { dd 7b [2] a9 63 [2] ee 61 [2] a9 70 [2] e7 7c [2] eb 76 [2] fc 7d [2] e7 33 [2] da }

  condition:
    any of them
}