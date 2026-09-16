rule TTP_XOR_MULT_DOSStub_3953 {
  strings:
    $key_3953 = { 6d 3b [2] 19 23 [2] 5e 21 [2] 19 30 [2] 57 3c [2] 5b 36 [2] 4c 3d [2] 57 73 [2] 6a }

  condition:
    any of them
}