rule TTP_XOR_MULT_DOSStub_56e2 {
  strings:
    $key_56e2 = { 02 8a [2] 76 92 [2] 31 90 [2] 76 81 [2] 38 8d [2] 34 87 [2] 23 8c [2] 38 c2 [2] 05 }

  condition:
    any of them
}