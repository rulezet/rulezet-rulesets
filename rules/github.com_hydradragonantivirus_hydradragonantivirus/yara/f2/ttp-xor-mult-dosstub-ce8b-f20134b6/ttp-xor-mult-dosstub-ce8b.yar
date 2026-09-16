rule TTP_XOR_MULT_DOSStub_ce8b {
  strings:
    $key_ce8b = { 9a e3 [2] ee fb [2] a9 f9 [2] ee e8 [2] a0 e4 [2] ac ee [2] bb e5 [2] a0 ab [2] 9d }

  condition:
    any of them
}