rule TTP_XOR_MULT_DOSStub_802f {
  strings:
    $key_802f = { d4 47 [2] a0 5f [2] e7 5d [2] a0 4c [2] ee 40 [2] e2 4a [2] f5 41 [2] ee 0f [2] d3 }

  condition:
    any of them
}