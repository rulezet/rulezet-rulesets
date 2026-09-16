rule TTP_XOR_MULT_DOSStub_ce92 {
  strings:
    $key_ce92 = { 9a fa [2] ee e2 [2] a9 e0 [2] ee f1 [2] a0 fd [2] ac f7 [2] bb fc [2] a0 b2 [2] 9d }

  condition:
    any of them
}