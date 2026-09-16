rule TTP_XOR_MULT_DOSStub_ce3a {
  strings:
    $key_ce3a = { 9a 52 [2] ee 4a [2] a9 48 [2] ee 59 [2] a0 55 [2] ac 5f [2] bb 54 [2] a0 1a [2] 9d }

  condition:
    any of them
}