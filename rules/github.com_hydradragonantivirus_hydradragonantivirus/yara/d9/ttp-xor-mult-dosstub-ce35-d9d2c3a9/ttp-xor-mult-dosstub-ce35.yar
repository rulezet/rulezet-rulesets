rule TTP_XOR_MULT_DOSStub_ce35 {
  strings:
    $key_ce35 = { 9a 5d [2] ee 45 [2] a9 47 [2] ee 56 [2] a0 5a [2] ac 50 [2] bb 5b [2] a0 15 [2] 9d }

  condition:
    any of them
}