rule TTP_XOR_MULT_DOSStub_bd92 {
  strings:
    $key_bd92 = { e9 fa [2] 9d e2 [2] da e0 [2] 9d f1 [2] d3 fd [2] df f7 [2] c8 fc [2] d3 b2 [2] ee }

  condition:
    any of them
}