rule TTP_XOR_MULT_DOSStub_8945 {
  strings:
    $key_8945 = { dd 2d [2] a9 35 [2] ee 37 [2] a9 26 [2] e7 2a [2] eb 20 [2] fc 2b [2] e7 65 [2] da }

  condition:
    any of them
}