rule TTP_XOR_MULT_DOSStub_46f5 {
  strings:
    $key_46f5 = { 12 9d [2] 66 85 [2] 21 87 [2] 66 96 [2] 28 9a [2] 24 90 [2] 33 9b [2] 28 d5 [2] 15 }

  condition:
    any of them
}