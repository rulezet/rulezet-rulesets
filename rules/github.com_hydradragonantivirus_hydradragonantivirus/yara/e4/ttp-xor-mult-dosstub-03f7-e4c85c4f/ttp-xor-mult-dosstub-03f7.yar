rule TTP_XOR_MULT_DOSStub_03f7 {
  strings:
    $key_03f7 = { 57 9f [2] 23 87 [2] 64 85 [2] 23 94 [2] 6d 98 [2] 61 92 [2] 76 99 [2] 6d d7 [2] 50 }

  condition:
    any of them
}