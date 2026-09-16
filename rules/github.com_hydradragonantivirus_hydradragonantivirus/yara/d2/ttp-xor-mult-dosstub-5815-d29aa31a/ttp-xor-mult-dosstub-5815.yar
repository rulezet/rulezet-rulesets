rule TTP_XOR_MULT_DOSStub_5815 {
  strings:
    $key_5815 = { 0c 7d [2] 78 65 [2] 3f 67 [2] 78 76 [2] 36 7a [2] 3a 70 [2] 2d 7b [2] 36 35 [2] 0b }

  condition:
    any of them
}