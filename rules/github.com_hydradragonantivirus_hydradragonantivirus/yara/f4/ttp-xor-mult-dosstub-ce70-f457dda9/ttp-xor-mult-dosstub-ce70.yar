rule TTP_XOR_MULT_DOSStub_ce70 {
  strings:
    $key_ce70 = { 9a 18 [2] ee 00 [2] a9 02 [2] ee 13 [2] a0 1f [2] ac 15 [2] bb 1e [2] a0 50 [2] 9d }

  condition:
    any of them
}