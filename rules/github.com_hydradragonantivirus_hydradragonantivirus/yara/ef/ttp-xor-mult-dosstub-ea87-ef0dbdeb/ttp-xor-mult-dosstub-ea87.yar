rule TTP_XOR_MULT_DOSStub_ea87 {
  strings:
    $key_ea87 = { be ef [2] ca f7 [2] 8d f5 [2] ca e4 [2] 84 e8 [2] 88 e2 [2] 9f e9 [2] 84 a7 [2] b9 }

  condition:
    any of them
}