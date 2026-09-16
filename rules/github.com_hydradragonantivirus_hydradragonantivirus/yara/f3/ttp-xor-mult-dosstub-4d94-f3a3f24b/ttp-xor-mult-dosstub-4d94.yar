rule TTP_XOR_MULT_DOSStub_4d94 {
  strings:
    $key_4d94 = { 19 fc [2] 6d e4 [2] 2a e6 [2] 6d f7 [2] 23 fb [2] 2f f1 [2] 38 fa [2] 23 b4 [2] 1e }

  condition:
    any of them
}