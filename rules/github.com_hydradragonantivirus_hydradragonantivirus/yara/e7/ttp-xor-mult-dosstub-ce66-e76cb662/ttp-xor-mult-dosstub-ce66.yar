rule TTP_XOR_MULT_DOSStub_ce66 {
  strings:
    $key_ce66 = { 9a 0e [2] ee 16 [2] a9 14 [2] ee 05 [2] a0 09 [2] ac 03 [2] bb 08 [2] a0 46 [2] 9d }

  condition:
    any of them
}