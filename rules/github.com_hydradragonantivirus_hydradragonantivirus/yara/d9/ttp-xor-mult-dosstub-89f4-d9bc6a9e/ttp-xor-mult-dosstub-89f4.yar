rule TTP_XOR_MULT_DOSStub_89f4 {
  strings:
    $key_89f4 = { dd 9c [2] a9 84 [2] ee 86 [2] a9 97 [2] e7 9b [2] eb 91 [2] fc 9a [2] e7 d4 [2] da }

  condition:
    any of them
}