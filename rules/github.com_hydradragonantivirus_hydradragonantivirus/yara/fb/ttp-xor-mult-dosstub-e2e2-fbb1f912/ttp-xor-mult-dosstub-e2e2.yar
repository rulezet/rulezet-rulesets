rule TTP_XOR_MULT_DOSStub_e2e2 {
  strings:
    $key_e2e2 = { b6 8a [2] c2 92 [2] 85 90 [2] c2 81 [2] 8c 8d [2] 80 87 [2] 97 8c [2] 8c c2 [2] b1 }

  condition:
    any of them
}