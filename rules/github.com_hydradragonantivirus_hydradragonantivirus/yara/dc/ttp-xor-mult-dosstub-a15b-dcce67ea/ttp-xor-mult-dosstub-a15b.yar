rule TTP_XOR_MULT_DOSStub_a15b {
  strings:
    $key_a15b = { f5 33 [2] 81 2b [2] c6 29 [2] 81 38 [2] cf 34 [2] c3 3e [2] d4 35 [2] cf 7b [2] f2 }

  condition:
    any of them
}