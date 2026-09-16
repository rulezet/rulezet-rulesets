rule TTP_XOR_MULT_DOSStub_1f94 {
  strings:
    $key_1f94 = { 4b fc [2] 3f e4 [2] 78 e6 [2] 3f f7 [2] 71 fb [2] 7d f1 [2] 6a fa [2] 71 b4 [2] 4c }

  condition:
    any of them
}