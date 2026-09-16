rule TTP_XOR_MULT_DOSStub_3353 {
  strings:
    $key_3353 = { 67 3b [2] 13 23 [2] 54 21 [2] 13 30 [2] 5d 3c [2] 51 36 [2] 46 3d [2] 5d 73 [2] 60 }

  condition:
    any of them
}