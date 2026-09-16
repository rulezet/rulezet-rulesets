rule TTP_XOR_MULT_DOSStub_cee0 {
  strings:
    $key_cee0 = { 9a 88 [2] ee 90 [2] a9 92 [2] ee 83 [2] a0 8f [2] ac 85 [2] bb 8e [2] a0 c0 [2] 9d }

  condition:
    any of them
}