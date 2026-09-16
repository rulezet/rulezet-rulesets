rule TTP_XOR_MULT_DOSStub_a1ea {
  strings:
    $key_a1ea = { f5 82 [2] 81 9a [2] c6 98 [2] 81 89 [2] cf 85 [2] c3 8f [2] d4 84 [2] cf ca [2] f2 }

  condition:
    any of them
}