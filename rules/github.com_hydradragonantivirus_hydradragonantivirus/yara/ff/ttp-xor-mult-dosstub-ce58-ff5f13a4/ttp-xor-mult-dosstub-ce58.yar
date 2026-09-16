rule TTP_XOR_MULT_DOSStub_ce58 {
  strings:
    $key_ce58 = { 9a 30 [2] ee 28 [2] a9 2a [2] ee 3b [2] a0 37 [2] ac 3d [2] bb 36 [2] a0 78 [2] 9d }

  condition:
    any of them
}