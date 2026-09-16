rule TTP_XOR_MULT_DOSStub_6d92 {
  strings:
    $key_6d92 = { 39 fa [2] 4d e2 [2] 0a e0 [2] 4d f1 [2] 03 fd [2] 0f f7 [2] 18 fc [2] 03 b2 [2] 3e }

  condition:
    any of them
}