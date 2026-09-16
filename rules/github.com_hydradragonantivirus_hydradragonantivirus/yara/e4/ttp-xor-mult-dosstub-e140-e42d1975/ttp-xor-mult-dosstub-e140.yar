rule TTP_XOR_MULT_DOSStub_e140 {
  strings:
    $key_e140 = { b5 28 [2] c1 30 [2] 86 32 [2] c1 23 [2] 8f 2f [2] 83 25 [2] 94 2e [2] 8f 60 [2] b2 }

  condition:
    any of them
}