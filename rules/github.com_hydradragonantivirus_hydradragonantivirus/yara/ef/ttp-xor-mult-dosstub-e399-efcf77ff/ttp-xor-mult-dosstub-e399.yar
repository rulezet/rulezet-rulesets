rule TTP_XOR_MULT_DOSStub_e399 {
  strings:
    $key_e399 = { b7 f1 [2] c3 e9 [2] 84 eb [2] c3 fa [2] 8d f6 [2] 81 fc [2] 96 f7 [2] 8d b9 [2] b0 }

  condition:
    any of them
}