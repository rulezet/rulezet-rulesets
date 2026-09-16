rule TTP_XOR_MULT_DOSStub_0153 {
  strings:
    $key_0153 = { 55 3b [2] 21 23 [2] 66 21 [2] 21 30 [2] 6f 3c [2] 63 36 [2] 74 3d [2] 6f 73 [2] 52 }

  condition:
    any of them
}