rule TTP_XOR_MULT_DOSStub_23e2 {
  strings:
    $key_23e2 = { 77 8a [2] 03 92 [2] 44 90 [2] 03 81 [2] 4d 8d [2] 41 87 [2] 56 8c [2] 4d c2 [2] 70 }

  condition:
    any of them
}