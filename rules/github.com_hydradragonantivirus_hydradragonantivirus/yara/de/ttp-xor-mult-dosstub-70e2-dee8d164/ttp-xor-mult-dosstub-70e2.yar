rule TTP_XOR_MULT_DOSStub_70e2 {
  strings:
    $key_70e2 = { 24 8a [2] 50 92 [2] 17 90 [2] 50 81 [2] 1e 8d [2] 12 87 [2] 05 8c [2] 1e c2 [2] 23 }

  condition:
    any of them
}