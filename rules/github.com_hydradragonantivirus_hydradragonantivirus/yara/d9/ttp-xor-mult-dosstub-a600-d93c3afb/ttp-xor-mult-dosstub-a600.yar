rule TTP_XOR_MULT_DOSStub_a600 {
  strings:
    $key_a600 = { f2 68 [2] 86 70 [2] c1 72 [2] 86 63 [2] c8 6f [2] c4 65 [2] d3 6e [2] c8 20 [2] f5 }

  condition:
    any of them
}