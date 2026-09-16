rule TTP_XOR_MULT_DOSStub_4a92 {
  strings:
    $key_4a92 = { 1e fa [2] 6a e2 [2] 2d e0 [2] 6a f1 [2] 24 fd [2] 28 f7 [2] 3f fc [2] 24 b2 [2] 19 }

  condition:
    any of them
}