rule TTP_XOR_MULT_DOSStub_8908 {
  strings:
    $key_8908 = { dd 60 [2] a9 78 [2] ee 7a [2] a9 6b [2] e7 67 [2] eb 6d [2] fc 66 [2] e7 28 [2] da }

  condition:
    any of them
}