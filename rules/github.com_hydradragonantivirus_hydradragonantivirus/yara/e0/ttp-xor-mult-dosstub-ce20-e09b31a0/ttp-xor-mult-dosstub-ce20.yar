rule TTP_XOR_MULT_DOSStub_ce20 {
  strings:
    $key_ce20 = { 9a 48 [2] ee 50 [2] a9 52 [2] ee 43 [2] a0 4f [2] ac 45 [2] bb 4e [2] a0 00 [2] 9d }

  condition:
    any of them
}