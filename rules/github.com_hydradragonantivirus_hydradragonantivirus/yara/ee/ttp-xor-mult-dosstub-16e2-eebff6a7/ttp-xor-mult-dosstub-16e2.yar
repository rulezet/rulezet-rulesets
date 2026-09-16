rule TTP_XOR_MULT_DOSStub_16e2 {
  strings:
    $key_16e2 = { 42 8a [2] 36 92 [2] 71 90 [2] 36 81 [2] 78 8d [2] 74 87 [2] 63 8c [2] 78 c2 [2] 45 }

  condition:
    any of them
}