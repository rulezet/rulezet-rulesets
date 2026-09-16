rule TTP_XOR_MULT_DOSStub_89f2 {
  strings:
    $key_89f2 = { dd 9a [2] a9 82 [2] ee 80 [2] a9 91 [2] e7 9d [2] eb 97 [2] fc 9c [2] e7 d2 [2] da }

  condition:
    any of them
}