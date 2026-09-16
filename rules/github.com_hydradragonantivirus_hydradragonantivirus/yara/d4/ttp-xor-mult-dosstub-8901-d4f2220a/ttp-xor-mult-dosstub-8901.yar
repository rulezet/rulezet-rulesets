rule TTP_XOR_MULT_DOSStub_8901 {
  strings:
    $key_8901 = { dd 69 [2] a9 71 [2] ee 73 [2] a9 62 [2] e7 6e [2] eb 64 [2] fc 6f [2] e7 21 [2] da }

  condition:
    any of them
}