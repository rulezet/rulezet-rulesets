rule TTP_XOR_MULT_DOSStub_51e2 {
  strings:
    $key_51e2 = { 05 8a [2] 71 92 [2] 36 90 [2] 71 81 [2] 3f 8d [2] 33 87 [2] 24 8c [2] 3f c2 [2] 02 }

  condition:
    any of them
}