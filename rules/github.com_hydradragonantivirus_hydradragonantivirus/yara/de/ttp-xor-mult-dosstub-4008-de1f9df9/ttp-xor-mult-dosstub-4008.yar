rule TTP_XOR_MULT_DOSStub_4008 {
  strings:
    $key_4008 = { 14 60 [2] 60 78 [2] 27 7a [2] 60 6b [2] 2e 67 [2] 22 6d [2] 35 66 [2] 2e 28 [2] 13 }

  condition:
    any of them
}