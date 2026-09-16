rule TTP_XOR_MULT_DOSStub_a1e6 {
  strings:
    $key_a1e6 = { f5 8e [2] 81 96 [2] c6 94 [2] 81 85 [2] cf 89 [2] c3 83 [2] d4 88 [2] cf c6 [2] f2 }

  condition:
    any of them
}