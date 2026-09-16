rule TTP_XOR_MULT_DOSStub_7003 {
  strings:
    $key_7003 = { 24 6b [2] 50 73 [2] 17 71 [2] 50 60 [2] 1e 6c [2] 12 66 [2] 05 6d [2] 1e 23 [2] 23 }

  condition:
    any of them
}