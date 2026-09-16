rule TTP_XOR_MULT_DOSStub_2303 {
  strings:
    $key_2303 = { 77 6b [2] 03 73 [2] 44 71 [2] 03 60 [2] 4d 6c [2] 41 66 [2] 56 6d [2] 4d 23 [2] 70 }

  condition:
    any of them
}