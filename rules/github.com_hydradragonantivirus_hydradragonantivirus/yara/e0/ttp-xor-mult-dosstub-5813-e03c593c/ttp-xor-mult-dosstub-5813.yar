rule TTP_XOR_MULT_DOSStub_5813 {
  strings:
    $key_5813 = { 0c 7b [2] 78 63 [2] 3f 61 [2] 78 70 [2] 36 7c [2] 3a 76 [2] 2d 7d [2] 36 33 [2] 0b }

  condition:
    any of them
}