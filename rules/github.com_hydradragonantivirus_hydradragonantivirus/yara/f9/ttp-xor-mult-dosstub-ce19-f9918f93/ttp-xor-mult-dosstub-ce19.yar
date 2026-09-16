rule TTP_XOR_MULT_DOSStub_ce19 {
  strings:
    $key_ce19 = { 9a 71 [2] ee 69 [2] a9 6b [2] ee 7a [2] a0 76 [2] ac 7c [2] bb 77 [2] a0 39 [2] 9d }

  condition:
    any of them
}