rule TTP_XOR_MULT_DOSStub_e3e2 {
  strings:
    $key_e3e2 = { b7 8a [2] c3 92 [2] 84 90 [2] c3 81 [2] 8d 8d [2] 81 87 [2] 96 8c [2] 8d c2 [2] b0 }

  condition:
    any of them
}