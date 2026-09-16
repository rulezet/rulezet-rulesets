rule TTP_XOR_MULT_DOSStub_5503 {
  strings:
    $key_5503 = { 01 6b [2] 75 73 [2] 32 71 [2] 75 60 [2] 3b 6c [2] 37 66 [2] 20 6d [2] 3b 23 [2] 06 }

  condition:
    any of them
}