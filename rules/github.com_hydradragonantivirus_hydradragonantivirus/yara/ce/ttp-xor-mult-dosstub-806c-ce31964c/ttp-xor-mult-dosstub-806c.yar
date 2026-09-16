rule TTP_XOR_MULT_DOSStub_806c {
  strings:
    $key_806c = { d4 04 [2] a0 1c [2] e7 1e [2] a0 0f [2] ee 03 [2] e2 09 [2] f5 02 [2] ee 4c [2] d3 }

  condition:
    any of them
}