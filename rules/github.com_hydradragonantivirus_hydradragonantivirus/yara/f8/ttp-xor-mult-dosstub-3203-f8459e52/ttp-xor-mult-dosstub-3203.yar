rule TTP_XOR_MULT_DOSStub_3203 {
  strings:
    $key_3203 = { 66 6b [2] 12 73 [2] 55 71 [2] 12 60 [2] 5c 6c [2] 50 66 [2] 47 6d [2] 5c 23 [2] 61 }

  condition:
    any of them
}