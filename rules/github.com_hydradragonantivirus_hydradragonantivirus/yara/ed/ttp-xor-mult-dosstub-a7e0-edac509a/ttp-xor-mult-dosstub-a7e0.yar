rule TTP_XOR_MULT_DOSStub_a7e0 {
  strings:
    $key_a7e0 = { f3 88 [2] 87 90 [2] c0 92 [2] 87 83 [2] c9 8f [2] c5 85 [2] d2 8e [2] c9 c0 [2] f4 }

  condition:
    any of them
}