rule TTP_XOR_MULT_DOSStub_61e2 {
  strings:
    $key_61e2 = { 35 8a [2] 41 92 [2] 06 90 [2] 41 81 [2] 0f 8d [2] 03 87 [2] 14 8c [2] 0f c2 [2] 32 }

  condition:
    any of them
}