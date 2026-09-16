rule TTP_XOR_MULT_DOSStub_a145 {
  strings:
    $key_a145 = { f5 2d [2] 81 35 [2] c6 37 [2] 81 26 [2] cf 2a [2] c3 20 [2] d4 2b [2] cf 65 [2] f2 }

  condition:
    any of them
}