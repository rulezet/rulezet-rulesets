rule TTP_XOR_MULT_DOSStub_bd94 {
  strings:
    $key_bd94 = { e9 fc [2] 9d e4 [2] da e6 [2] 9d f7 [2] d3 fb [2] df f1 [2] c8 fa [2] d3 b4 [2] ee }

  condition:
    any of them
}