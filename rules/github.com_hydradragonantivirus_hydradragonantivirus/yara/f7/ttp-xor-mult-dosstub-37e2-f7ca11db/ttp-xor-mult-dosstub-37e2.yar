rule TTP_XOR_MULT_DOSStub_37e2 {
  strings:
    $key_37e2 = { 63 8a [2] 17 92 [2] 50 90 [2] 17 81 [2] 59 8d [2] 55 87 [2] 42 8c [2] 59 c2 [2] 64 }

  condition:
    any of them
}