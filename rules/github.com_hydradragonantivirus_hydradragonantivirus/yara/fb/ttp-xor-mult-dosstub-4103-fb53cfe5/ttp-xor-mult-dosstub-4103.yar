rule TTP_XOR_MULT_DOSStub_4103 {
  strings:
    $key_4103 = { 15 6b [2] 61 73 [2] 26 71 [2] 61 60 [2] 2f 6c [2] 23 66 [2] 34 6d [2] 2f 23 [2] 12 }

  condition:
    any of them
}