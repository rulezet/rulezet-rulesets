rule TTP_XOR_MULT_DOSStub_51e9 {
  strings:
    $key_51e9 = { 05 81 [2] 71 99 [2] 36 9b [2] 71 8a [2] 3f 86 [2] 33 8c [2] 24 87 [2] 3f c9 [2] 02 }

  condition:
    any of them
}