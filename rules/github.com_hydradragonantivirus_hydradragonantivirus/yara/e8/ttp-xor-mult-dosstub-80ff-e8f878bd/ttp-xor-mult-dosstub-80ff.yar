rule TTP_XOR_MULT_DOSStub_80ff {
  strings:
    $key_80ff = { d4 97 [2] a0 8f [2] e7 8d [2] a0 9c [2] ee 90 [2] e2 9a [2] f5 91 [2] ee df [2] d3 }

  condition:
    any of them
}