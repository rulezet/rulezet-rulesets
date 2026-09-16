rule TTP_XOR_MULT_DOSStub_a116 {
  strings:
    $key_a116 = { f5 7e [2] 81 66 [2] c6 64 [2] 81 75 [2] cf 79 [2] c3 73 [2] d4 78 [2] cf 36 [2] f2 }

  condition:
    any of them
}