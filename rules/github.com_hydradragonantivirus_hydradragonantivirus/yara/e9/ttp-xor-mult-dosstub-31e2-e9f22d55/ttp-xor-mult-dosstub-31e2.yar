rule TTP_XOR_MULT_DOSStub_31e2 {
  strings:
    $key_31e2 = { 65 8a [2] 11 92 [2] 56 90 [2] 11 81 [2] 5f 8d [2] 53 87 [2] 44 8c [2] 5f c2 [2] 62 }

  condition:
    any of them
}