rule TTP_XOR_MULT_DOSStub_a150 {
  strings:
    $key_a150 = { f5 38 [2] 81 20 [2] c6 22 [2] 81 33 [2] cf 3f [2] c3 35 [2] d4 3e [2] cf 70 [2] f2 }

  condition:
    any of them
}