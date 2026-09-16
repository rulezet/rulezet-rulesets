rule TTP_XOR_MULT_DOSStub_a751 {
  strings:
    $key_a751 = { f3 39 [2] 87 21 [2] c0 23 [2] 87 32 [2] c9 3e [2] c5 34 [2] d2 3f [2] c9 71 [2] f4 }

  condition:
    any of them
}