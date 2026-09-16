rule TTP_XOR_MULT_DOSStub_cee8 {
  strings:
    $key_cee8 = { 9a 80 [2] ee 98 [2] a9 9a [2] ee 8b [2] a0 87 [2] ac 8d [2] bb 86 [2] a0 c8 [2] 9d }

  condition:
    any of them
}