rule TTP_XOR_MULT_DOSStub_3f94 {
  strings:
    $key_3f94 = { 6b fc [2] 1f e4 [2] 58 e6 [2] 1f f7 [2] 51 fb [2] 5d f1 [2] 4a fa [2] 51 b4 [2] 6c }

  condition:
    any of them
}