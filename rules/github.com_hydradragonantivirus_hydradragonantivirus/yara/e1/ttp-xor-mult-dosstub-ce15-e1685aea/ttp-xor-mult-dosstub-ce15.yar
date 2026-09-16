rule TTP_XOR_MULT_DOSStub_ce15 {
  strings:
    $key_ce15 = { 9a 7d [2] ee 65 [2] a9 67 [2] ee 76 [2] a0 7a [2] ac 70 [2] bb 7b [2] a0 35 [2] 9d }

  condition:
    any of them
}