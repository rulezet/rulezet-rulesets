rule TTP_XOR_MULT_DOSStub_6a92 {
  strings:
    $key_6a92 = { 3e fa [2] 4a e2 [2] 0d e0 [2] 4a f1 [2] 04 fd [2] 08 f7 [2] 1f fc [2] 04 b2 [2] 39 }

  condition:
    any of them
}