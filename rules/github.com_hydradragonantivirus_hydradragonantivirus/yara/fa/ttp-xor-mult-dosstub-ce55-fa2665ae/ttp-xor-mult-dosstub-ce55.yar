rule TTP_XOR_MULT_DOSStub_ce55 {
  strings:
    $key_ce55 = { 9a 3d [2] ee 25 [2] a9 27 [2] ee 36 [2] a0 3a [2] ac 30 [2] bb 3b [2] a0 75 [2] 9d }

  condition:
    any of them
}