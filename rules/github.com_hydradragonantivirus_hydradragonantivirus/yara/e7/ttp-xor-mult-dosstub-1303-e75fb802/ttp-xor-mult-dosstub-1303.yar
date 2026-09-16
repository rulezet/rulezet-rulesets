rule TTP_XOR_MULT_DOSStub_1303 {
  strings:
    $key_1303 = { 47 6b [2] 33 73 [2] 74 71 [2] 33 60 [2] 7d 6c [2] 71 66 [2] 66 6d [2] 7d 23 [2] 40 }

  condition:
    any of them
}