rule TTP_XOR_MULT_DOSStub_ce3b {
  strings:
    $key_ce3b = { 9a 53 [2] ee 4b [2] a9 49 [2] ee 58 [2] a0 54 [2] ac 5e [2] bb 55 [2] a0 1b [2] 9d }

  condition:
    any of them
}