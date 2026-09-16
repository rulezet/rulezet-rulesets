rule TTP_XOR_MULT_DOSStub_8957 {
  strings:
    $key_8957 = { dd 3f [2] a9 27 [2] ee 25 [2] a9 34 [2] e7 38 [2] eb 32 [2] fc 39 [2] e7 77 [2] da }

  condition:
    any of them
}