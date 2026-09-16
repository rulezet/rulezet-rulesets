rule TTP_XOR_MULT_DOSStub_e1e4 {
  strings:
    $key_e1e4 = { b5 8c [2] c1 94 [2] 86 96 [2] c1 87 [2] 8f 8b [2] 83 81 [2] 94 8a [2] 8f c4 [2] b2 }

  condition:
    any of them
}