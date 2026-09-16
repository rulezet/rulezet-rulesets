rule TTP_XOR_MULT_DOSStub_33f7 {
  strings:
    $key_33f7 = { 67 9f [2] 13 87 [2] 54 85 [2] 13 94 [2] 5d 98 [2] 51 92 [2] 46 99 [2] 5d d7 [2] 60 }

  condition:
    any of them
}