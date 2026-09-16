rule TTP_XOR_MULT_DOSStub_3303 {
  strings:
    $key_3303 = { 67 6b [2] 13 73 [2] 54 71 [2] 13 60 [2] 5d 6c [2] 51 66 [2] 46 6d [2] 5d 23 [2] 60 }

  condition:
    any of them
}