rule TTP_XOR_MULT_DOSStub_ce2d {
  strings:
    $key_ce2d = { 9a 45 [2] ee 5d [2] a9 5f [2] ee 4e [2] a0 42 [2] ac 48 [2] bb 43 [2] a0 0d [2] 9d }

  condition:
    any of them
}