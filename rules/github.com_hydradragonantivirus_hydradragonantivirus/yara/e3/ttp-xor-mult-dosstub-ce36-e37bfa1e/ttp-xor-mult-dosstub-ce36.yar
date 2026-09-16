rule TTP_XOR_MULT_DOSStub_ce36 {
  strings:
    $key_ce36 = { 9a 5e [2] ee 46 [2] a9 44 [2] ee 55 [2] a0 59 [2] ac 53 [2] bb 58 [2] a0 16 [2] 9d }

  condition:
    any of them
}