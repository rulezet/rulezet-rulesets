rule TTP_XOR_MULT_DOSStub_a7e1 {
  strings:
    $key_a7e1 = { f3 89 [2] 87 91 [2] c0 93 [2] 87 82 [2] c9 8e [2] c5 84 [2] d2 8f [2] c9 c1 [2] f4 }

  condition:
    any of them
}