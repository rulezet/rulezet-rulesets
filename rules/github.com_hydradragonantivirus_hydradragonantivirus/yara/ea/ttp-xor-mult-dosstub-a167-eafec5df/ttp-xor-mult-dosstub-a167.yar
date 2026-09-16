rule TTP_XOR_MULT_DOSStub_a167 {
  strings:
    $key_a167 = { f5 0f [2] 81 17 [2] c6 15 [2] 81 04 [2] cf 08 [2] c3 02 [2] d4 09 [2] cf 47 [2] f2 }

  condition:
    any of them
}