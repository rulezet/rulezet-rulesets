rule TTP_XOR_MULT_DOSStub_ce08 {
  strings:
    $key_ce08 = { 9a 60 [2] ee 78 [2] a9 7a [2] ee 6b [2] a0 67 [2] ac 6d [2] bb 66 [2] a0 28 [2] 9d }

  condition:
    any of them
}