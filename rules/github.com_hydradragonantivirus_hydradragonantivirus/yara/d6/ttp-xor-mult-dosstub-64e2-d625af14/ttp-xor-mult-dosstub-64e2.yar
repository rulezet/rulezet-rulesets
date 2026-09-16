rule TTP_XOR_MULT_DOSStub_64e2 {
  strings:
    $key_64e2 = { 30 8a [2] 44 92 [2] 03 90 [2] 44 81 [2] 0a 8d [2] 06 87 [2] 11 8c [2] 0a c2 [2] 37 }

  condition:
    any of them
}