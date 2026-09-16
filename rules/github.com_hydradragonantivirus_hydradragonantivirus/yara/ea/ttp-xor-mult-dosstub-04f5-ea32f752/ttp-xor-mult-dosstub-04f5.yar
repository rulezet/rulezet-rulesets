rule TTP_XOR_MULT_DOSStub_04f5 {
  strings:
    $key_04f5 = { 50 9d [2] 24 85 [2] 63 87 [2] 24 96 [2] 6a 9a [2] 66 90 [2] 71 9b [2] 6a d5 [2] 57 }

  condition:
    any of them
}