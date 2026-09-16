rule TTP_XOR_MULT_DOSStub_ce43 {
  strings:
    $key_ce43 = { 9a 2b [2] ee 33 [2] a9 31 [2] ee 20 [2] a0 2c [2] ac 26 [2] bb 2d [2] a0 63 [2] 9d }

  condition:
    any of them
}