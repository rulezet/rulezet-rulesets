rule TTP_XOR_MULT_DOSStub_ce95 {
  strings:
    $key_ce95 = { 9a fd [2] ee e5 [2] a9 e7 [2] ee f6 [2] a0 fa [2] ac f0 [2] bb fb [2] a0 b5 [2] 9d }

  condition:
    any of them
}