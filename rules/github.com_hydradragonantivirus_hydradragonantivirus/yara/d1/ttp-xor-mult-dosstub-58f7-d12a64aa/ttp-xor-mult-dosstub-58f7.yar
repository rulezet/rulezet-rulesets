rule TTP_XOR_MULT_DOSStub_58f7 {
  strings:
    $key_58f7 = { 0c 9f [2] 78 87 [2] 3f 85 [2] 78 94 [2] 36 98 [2] 3a 92 [2] 2d 99 [2] 36 d7 [2] 0b }

  condition:
    any of them
}