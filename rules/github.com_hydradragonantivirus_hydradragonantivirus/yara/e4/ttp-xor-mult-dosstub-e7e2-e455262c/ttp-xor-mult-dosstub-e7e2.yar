rule TTP_XOR_MULT_DOSStub_e7e2 {
  strings:
    $key_e7e2 = { b3 8a [2] c7 92 [2] 80 90 [2] c7 81 [2] 89 8d [2] 85 87 [2] 92 8c [2] 89 c2 [2] b4 }

  condition:
    any of them
}