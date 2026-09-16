rule TTP_XOR_MULT_DOSStub_33e2 {
  strings:
    $key_33e2 = { 67 8a [2] 13 92 [2] 54 90 [2] 13 81 [2] 5d 8d [2] 51 87 [2] 46 8c [2] 5d c2 [2] 60 }

  condition:
    any of them
}