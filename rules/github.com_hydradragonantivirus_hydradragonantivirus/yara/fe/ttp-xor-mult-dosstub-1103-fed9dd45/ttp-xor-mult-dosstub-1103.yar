rule TTP_XOR_MULT_DOSStub_1103 {
  strings:
    $key_1103 = { 45 6b [2] 31 73 [2] 76 71 [2] 31 60 [2] 7f 6c [2] 73 66 [2] 64 6d [2] 7f 23 [2] 42 }

  condition:
    any of them
}