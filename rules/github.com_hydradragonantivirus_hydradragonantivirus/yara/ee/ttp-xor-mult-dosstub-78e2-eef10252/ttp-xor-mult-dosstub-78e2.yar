rule TTP_XOR_MULT_DOSStub_78e2 {
  strings:
    $key_78e2 = { 2c 8a [2] 58 92 [2] 1f 90 [2] 58 81 [2] 16 8d [2] 1a 87 [2] 0d 8c [2] 16 c2 [2] 2b }

  condition:
    any of them
}