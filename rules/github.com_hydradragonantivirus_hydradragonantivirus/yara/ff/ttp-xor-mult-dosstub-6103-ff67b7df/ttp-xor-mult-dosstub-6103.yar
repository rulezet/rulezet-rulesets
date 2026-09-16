rule TTP_XOR_MULT_DOSStub_6103 {
  strings:
    $key_6103 = { 35 6b [2] 41 73 [2] 06 71 [2] 41 60 [2] 0f 6c [2] 03 66 [2] 14 6d [2] 0f 23 [2] 32 }

  condition:
    any of them
}