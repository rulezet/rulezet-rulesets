rule TTP_XOR_MULT_DOSStub_b7e2 {
  strings:
    $key_b7e2 = { e3 8a [2] 97 92 [2] d0 90 [2] 97 81 [2] d9 8d [2] d5 87 [2] c2 8c [2] d9 c2 [2] e4 }

  condition:
    any of them
}