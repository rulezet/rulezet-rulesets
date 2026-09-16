rule TTP_XOR_MULT_DOSStub_57e2 {
  strings:
    $key_57e2 = { 03 8a [2] 77 92 [2] 30 90 [2] 77 81 [2] 39 8d [2] 35 87 [2] 22 8c [2] 39 c2 [2] 04 }

  condition:
    any of them
}