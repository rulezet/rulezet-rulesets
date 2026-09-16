rule TTP_XOR_MULT_DOSStub_cef1 {
  strings:
    $key_cef1 = { 9a 99 [2] ee 81 [2] a9 83 [2] ee 92 [2] a0 9e [2] ac 94 [2] bb 9f [2] a0 d1 [2] 9d }

  condition:
    any of them
}