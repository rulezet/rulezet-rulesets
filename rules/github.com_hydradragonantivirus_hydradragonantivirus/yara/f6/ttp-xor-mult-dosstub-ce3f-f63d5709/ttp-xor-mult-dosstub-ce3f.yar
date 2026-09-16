rule TTP_XOR_MULT_DOSStub_ce3f {
  strings:
    $key_ce3f = { 9a 57 [2] ee 4f [2] a9 4d [2] ee 5c [2] a0 50 [2] ac 5a [2] bb 51 [2] a0 1f [2] 9d }

  condition:
    any of them
}