rule TTP_XOR_MULT_DOSStub_2203 {
  strings:
    $key_2203 = { 76 6b [2] 02 73 [2] 45 71 [2] 02 60 [2] 4c 6c [2] 40 66 [2] 57 6d [2] 4c 23 [2] 71 }

  condition:
    any of them
}