rule TTP_XOR_MULT_DOSStub_00e2 {
  strings:
    $key_00e2 = { 54 8a [2] 20 92 [2] 67 90 [2] 20 81 [2] 6e 8d [2] 62 87 [2] 75 8c [2] 6e c2 [2] 53 }

  condition:
    any of them
}