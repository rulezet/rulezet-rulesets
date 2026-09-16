rule TTP_XOR_MULT_DOSStub_7088 {
  strings:
    $key_7088 = { 24 e0 [2] 50 f8 [2] 17 fa [2] 50 eb [2] 1e e7 [2] 12 ed [2] 05 e6 [2] 1e a8 [2] 23 }

  condition:
    any of them
}