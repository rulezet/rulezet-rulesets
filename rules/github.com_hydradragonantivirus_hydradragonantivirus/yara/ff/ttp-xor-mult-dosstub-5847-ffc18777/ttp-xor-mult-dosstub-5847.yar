rule TTP_XOR_MULT_DOSStub_5847 {
  strings:
    $key_5847 = { 0c 2f [2] 78 37 [2] 3f 35 [2] 78 24 [2] 36 28 [2] 3a 22 [2] 2d 29 [2] 36 67 [2] 0b }

  condition:
    any of them
}