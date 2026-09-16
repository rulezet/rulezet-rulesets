rule TTP_XOR_MULT_DOSStub_4004 {
  strings:
    $key_4004 = { 14 6c [2] 60 74 [2] 27 76 [2] 60 67 [2] 2e 6b [2] 22 61 [2] 35 6a [2] 2e 24 [2] 13 }

  condition:
    any of them
}