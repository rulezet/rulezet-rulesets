rule TTP_XOR_MULT_DOSStub_ce1e {
  strings:
    $key_ce1e = { 9a 76 [2] ee 6e [2] a9 6c [2] ee 7d [2] a0 71 [2] ac 7b [2] bb 70 [2] a0 3e [2] 9d }

  condition:
    any of them
}