rule TTP_XOR_MULT_DOSStub_ce44 {
  strings:
    $key_ce44 = { 9a 2c [2] ee 34 [2] a9 36 [2] ee 27 [2] a0 2b [2] ac 21 [2] bb 2a [2] a0 64 [2] 9d }

  condition:
    any of them
}