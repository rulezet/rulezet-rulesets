rule TTP_XOR_MULT_DOSStub_ce37 {
  strings:
    $key_ce37 = { 9a 5f [2] ee 47 [2] a9 45 [2] ee 54 [2] a0 58 [2] ac 52 [2] bb 59 [2] a0 17 [2] 9d }

  condition:
    any of them
}