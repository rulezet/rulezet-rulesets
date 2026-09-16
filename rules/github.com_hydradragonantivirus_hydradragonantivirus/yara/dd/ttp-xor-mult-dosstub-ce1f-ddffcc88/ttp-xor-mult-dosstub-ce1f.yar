rule TTP_XOR_MULT_DOSStub_ce1f {
  strings:
    $key_ce1f = { 9a 77 [2] ee 6f [2] a9 6d [2] ee 7c [2] a0 70 [2] ac 7a [2] bb 71 [2] a0 3f [2] 9d }

  condition:
    any of them
}