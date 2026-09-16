rule TTP_XOR_MULT_DOSStub_ce81 {
  strings:
    $key_ce81 = { 9a e9 [2] ee f1 [2] a9 f3 [2] ee e2 [2] a0 ee [2] ac e4 [2] bb ef [2] a0 a1 [2] 9d }

  condition:
    any of them
}