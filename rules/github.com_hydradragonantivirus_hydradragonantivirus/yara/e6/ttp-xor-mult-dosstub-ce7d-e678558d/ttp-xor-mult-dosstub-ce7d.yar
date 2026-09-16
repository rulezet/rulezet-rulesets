rule TTP_XOR_MULT_DOSStub_ce7d {
  strings:
    $key_ce7d = { 9a 15 [2] ee 0d [2] a9 0f [2] ee 1e [2] a0 12 [2] ac 18 [2] bb 13 [2] a0 5d [2] 9d }

  condition:
    any of them
}