rule TTP_XOR_MULT_DOSStub_e1f5 {
  strings:
    $key_e1f5 = { b5 9d [2] c1 85 [2] 86 87 [2] c1 96 [2] 8f 9a [2] 83 90 [2] 94 9b [2] 8f d5 [2] b2 }

  condition:
    any of them
}