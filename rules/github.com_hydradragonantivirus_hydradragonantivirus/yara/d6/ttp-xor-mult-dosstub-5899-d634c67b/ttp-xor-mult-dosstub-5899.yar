rule TTP_XOR_MULT_DOSStub_5899 {
  strings:
    $key_5899 = { 0c f1 [2] 78 e9 [2] 3f eb [2] 78 fa [2] 36 f6 [2] 3a fc [2] 2d f7 [2] 36 b9 [2] 0b }

  condition:
    any of them
}