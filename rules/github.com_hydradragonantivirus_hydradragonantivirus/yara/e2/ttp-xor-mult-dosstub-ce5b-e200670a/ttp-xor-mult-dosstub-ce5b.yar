rule TTP_XOR_MULT_DOSStub_ce5b {
  strings:
    $key_ce5b = { 9a 33 [2] ee 2b [2] a9 29 [2] ee 38 [2] a0 34 [2] ac 3e [2] bb 35 [2] a0 7b [2] 9d }

  condition:
    any of them
}