rule TTP_XOR_MULT_DOSStub_806b {
  strings:
    $key_806b = { d4 03 [2] a0 1b [2] e7 19 [2] a0 08 [2] ee 04 [2] e2 0e [2] f5 05 [2] ee 4b [2] d3 }

  condition:
    any of them
}