rule TTP_XOR_MULT_DOSStub_43e2 {
  strings:
    $key_43e2 = { 17 8a [2] 63 92 [2] 24 90 [2] 63 81 [2] 2d 8d [2] 21 87 [2] 36 8c [2] 2d c2 [2] 10 }

  condition:
    any of them
}