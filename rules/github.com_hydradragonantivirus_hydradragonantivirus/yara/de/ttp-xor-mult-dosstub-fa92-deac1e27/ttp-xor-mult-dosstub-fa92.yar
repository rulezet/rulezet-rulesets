rule TTP_XOR_MULT_DOSStub_fa92 {
  strings:
    $key_fa92 = { ae fa [2] da e2 [2] 9d e0 [2] da f1 [2] 94 fd [2] 98 f7 [2] 8f fc [2] 94 b2 [2] a9 }

  condition:
    any of them
}