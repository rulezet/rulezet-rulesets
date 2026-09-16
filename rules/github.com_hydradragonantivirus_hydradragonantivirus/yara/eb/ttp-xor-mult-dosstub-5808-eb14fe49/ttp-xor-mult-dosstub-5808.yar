rule TTP_XOR_MULT_DOSStub_5808 {
  strings:
    $key_5808 = { 0c 60 [2] 78 78 [2] 3f 7a [2] 78 6b [2] 36 67 [2] 3a 6d [2] 2d 66 [2] 36 28 [2] 0b }

  condition:
    any of them
}