rule TTP_XOR_MULT_DOSStub_ce56 {
  strings:
    $key_ce56 = { 9a 3e [2] ee 26 [2] a9 24 [2] ee 35 [2] a0 39 [2] ac 33 [2] bb 38 [2] a0 76 [2] 9d }

  condition:
    any of them
}