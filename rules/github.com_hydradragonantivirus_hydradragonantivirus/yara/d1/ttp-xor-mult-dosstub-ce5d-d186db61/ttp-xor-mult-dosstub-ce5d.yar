rule TTP_XOR_MULT_DOSStub_ce5d {
  strings:
    $key_ce5d = { 9a 35 [2] ee 2d [2] a9 2f [2] ee 3e [2] a0 32 [2] ac 38 [2] bb 33 [2] a0 7d [2] 9d }

  condition:
    any of them
}