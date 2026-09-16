rule TTP_XOR_MULT_DOSStub_e0e2 {
  strings:
    $key_e0e2 = { b4 8a [2] c0 92 [2] 87 90 [2] c0 81 [2] 8e 8d [2] 82 87 [2] 95 8c [2] 8e c2 [2] b3 }

  condition:
    any of them
}