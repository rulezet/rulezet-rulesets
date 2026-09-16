rule TTP_XOR_MULT_DOSStub_7ae2 {
  strings:
    $key_7ae2 = { 2e 8a [2] 5a 92 [2] 1d 90 [2] 5a 81 [2] 14 8d [2] 18 87 [2] 0f 8c [2] 14 c2 [2] 29 }

  condition:
    any of them
}