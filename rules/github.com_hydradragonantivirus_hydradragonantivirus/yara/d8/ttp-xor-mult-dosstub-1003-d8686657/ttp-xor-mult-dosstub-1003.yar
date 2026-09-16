rule TTP_XOR_MULT_DOSStub_1003 {
  strings:
    $key_1003 = { 44 6b [2] 30 73 [2] 77 71 [2] 30 60 [2] 7e 6c [2] 72 66 [2] 65 6d [2] 7e 23 [2] 43 }

  condition:
    any of them
}