rule TTP_XOR_MULT_DOSStub_8924 {
  strings:
    $key_8924 = { dd 4c [2] a9 54 [2] ee 56 [2] a9 47 [2] e7 4b [2] eb 41 [2] fc 4a [2] e7 04 [2] da }

  condition:
    any of them
}