rule TTP_XOR_MULT_DOSStub_ce30 {
  strings:
    $key_ce30 = { 9a 58 [2] ee 40 [2] a9 42 [2] ee 53 [2] a0 5f [2] ac 55 [2] bb 5e [2] a0 10 [2] 9d }

  condition:
    any of them
}