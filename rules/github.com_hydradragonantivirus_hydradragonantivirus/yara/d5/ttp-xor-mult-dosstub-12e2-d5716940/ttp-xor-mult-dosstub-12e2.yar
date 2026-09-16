rule TTP_XOR_MULT_DOSStub_12e2 {
  strings:
    $key_12e2 = { 46 8a [2] 32 92 [2] 75 90 [2] 32 81 [2] 7c 8d [2] 70 87 [2] 67 8c [2] 7c c2 [2] 41 }

  condition:
    any of them
}