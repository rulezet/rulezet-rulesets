rule TTP_XOR_MULT_DOSStub_ea92 {
  strings:
    $key_ea92 = { be fa [2] ca e2 [2] 8d e0 [2] ca f1 [2] 84 fd [2] 88 f7 [2] 9f fc [2] 84 b2 [2] b9 }

  condition:
    any of them
}