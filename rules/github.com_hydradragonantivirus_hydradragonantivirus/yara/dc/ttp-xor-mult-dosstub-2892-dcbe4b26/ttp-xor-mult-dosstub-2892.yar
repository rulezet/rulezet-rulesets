rule TTP_XOR_MULT_DOSStub_2892 {
  strings:
    $key_2892 = { 7c fa [2] 08 e2 [2] 4f e0 [2] 08 f1 [2] 46 fd [2] 4a f7 [2] 5d fc [2] 46 b2 [2] 7b }

  condition:
    any of them
}