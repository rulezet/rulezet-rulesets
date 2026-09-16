rule TTP_XOR_MULT_DOSStub_ea95 {
  strings:
    $key_ea95 = { be fd [2] ca e5 [2] 8d e7 [2] ca f6 [2] 84 fa [2] 88 f0 [2] 9f fb [2] 84 b5 [2] b9 }

  condition:
    any of them
}