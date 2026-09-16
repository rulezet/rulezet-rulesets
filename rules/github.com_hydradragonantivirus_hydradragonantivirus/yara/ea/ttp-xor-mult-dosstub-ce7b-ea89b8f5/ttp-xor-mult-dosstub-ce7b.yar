rule TTP_XOR_MULT_DOSStub_ce7b {
  strings:
    $key_ce7b = { 9a 13 [2] ee 0b [2] a9 09 [2] ee 18 [2] a0 14 [2] ac 1e [2] bb 15 [2] a0 5b [2] 9d }

  condition:
    any of them
}