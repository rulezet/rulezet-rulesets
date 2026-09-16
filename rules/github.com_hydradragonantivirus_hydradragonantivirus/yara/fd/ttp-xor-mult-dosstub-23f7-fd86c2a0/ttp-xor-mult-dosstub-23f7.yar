rule TTP_XOR_MULT_DOSStub_23f7 {
  strings:
    $key_23f7 = { 77 9f [2] 03 87 [2] 44 85 [2] 03 94 [2] 4d 98 [2] 41 92 [2] 56 99 [2] 4d d7 [2] 70 }

  condition:
    any of them
}