rule TTP_XOR_MULT_DOSStub_e1f0 {
  strings:
    $key_e1f0 = { b5 98 [2] c1 80 [2] 86 82 [2] c1 93 [2] 8f 9f [2] 83 95 [2] 94 9e [2] 8f d0 [2] b2 }

  condition:
    any of them
}