rule TTP_XOR_MULT_DOSStub_3503 {
  strings:
    $key_3503 = { 61 6b [2] 15 73 [2] 52 71 [2] 15 60 [2] 5b 6c [2] 57 66 [2] 40 6d [2] 5b 23 [2] 66 }

  condition:
    any of them
}