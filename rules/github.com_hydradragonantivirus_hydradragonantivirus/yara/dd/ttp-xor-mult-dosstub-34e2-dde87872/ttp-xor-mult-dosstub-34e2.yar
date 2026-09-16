rule TTP_XOR_MULT_DOSStub_34e2 {
  strings:
    $key_34e2 = { 60 8a [2] 14 92 [2] 53 90 [2] 14 81 [2] 5a 8d [2] 56 87 [2] 41 8c [2] 5a c2 [2] 67 }

  condition:
    any of them
}