rule TTP_XOR_MULT_DOSStub_e1f1 {
  strings:
    $key_e1f1 = { b5 99 [2] c1 81 [2] 86 83 [2] c1 92 [2] 8f 9e [2] 83 94 [2] 94 9f [2] 8f d1 [2] b2 }

  condition:
    any of them
}