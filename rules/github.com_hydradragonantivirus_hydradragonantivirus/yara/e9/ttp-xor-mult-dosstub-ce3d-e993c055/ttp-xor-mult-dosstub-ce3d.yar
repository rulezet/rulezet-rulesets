rule TTP_XOR_MULT_DOSStub_ce3d {
  strings:
    $key_ce3d = { 9a 55 [2] ee 4d [2] a9 4f [2] ee 5e [2] a0 52 [2] ac 58 [2] bb 53 [2] a0 1d [2] 9d }

  condition:
    any of them
}