rule TTP_XOR_MULT_DOSStub_4153 {
  strings:
    $key_4153 = { 15 3b [2] 61 23 [2] 26 21 [2] 61 30 [2] 2f 3c [2] 23 36 [2] 34 3d [2] 2f 73 [2] 12 }

  condition:
    any of them
}