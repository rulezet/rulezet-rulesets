rule TTP_XOR_MULT_DOSStub_a171 {
  strings:
    $key_a171 = { f5 19 [2] 81 01 [2] c6 03 [2] 81 12 [2] cf 1e [2] c3 14 [2] d4 1f [2] cf 51 [2] f2 }

  condition:
    any of them
}