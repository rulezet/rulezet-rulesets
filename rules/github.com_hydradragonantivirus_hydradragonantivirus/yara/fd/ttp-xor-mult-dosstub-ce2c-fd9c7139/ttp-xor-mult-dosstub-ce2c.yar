rule TTP_XOR_MULT_DOSStub_ce2c {
  strings:
    $key_ce2c = { 9a 44 [2] ee 5c [2] a9 5e [2] ee 4f [2] a0 43 [2] ac 49 [2] bb 42 [2] a0 0c [2] 9d }

  condition:
    any of them
}