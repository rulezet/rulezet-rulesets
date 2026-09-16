rule TTP_XOR_MULT_DOSStub_1853 {
  strings:
    $key_1853 = { 4c 3b [2] 38 23 [2] 7f 21 [2] 38 30 [2] 76 3c [2] 7a 36 [2] 6d 3d [2] 76 73 [2] 4b }

  condition:
    any of them
}