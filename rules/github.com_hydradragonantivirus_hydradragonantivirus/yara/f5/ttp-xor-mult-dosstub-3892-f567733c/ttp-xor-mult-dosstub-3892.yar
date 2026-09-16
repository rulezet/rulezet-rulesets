rule TTP_XOR_MULT_DOSStub_3892 {
  strings:
    $key_3892 = { 6c fa [2] 18 e2 [2] 5f e0 [2] 18 f1 [2] 56 fd [2] 5a f7 [2] 4d fc [2] 56 b2 [2] 6b }

  condition:
    any of them
}