rule TTP_XOR_MULT_DOSStub_ceeb {
  strings:
    $key_ceeb = { 9a 83 [2] ee 9b [2] a9 99 [2] ee 88 [2] a0 84 [2] ac 8e [2] bb 85 [2] a0 cb [2] 9d }

  condition:
    any of them
}