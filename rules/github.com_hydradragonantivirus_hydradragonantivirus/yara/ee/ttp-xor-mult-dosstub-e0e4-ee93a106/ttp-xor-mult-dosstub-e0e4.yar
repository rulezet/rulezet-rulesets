rule TTP_XOR_MULT_DOSStub_e0e4 {
  strings:
    $key_e0e4 = { b4 8c [2] c0 94 [2] 87 96 [2] c0 87 [2] 8e 8b [2] 82 81 [2] 95 8a [2] 8e c4 [2] b3 }

  condition:
    any of them
}