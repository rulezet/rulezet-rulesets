rule TTP_XOR_MULT_DOSStub_a1a2 {
  strings:
    $key_a1a2 = { f5 ca [2] 81 d2 [2] c6 d0 [2] 81 c1 [2] cf cd [2] c3 c7 [2] d4 cc [2] cf 82 [2] f2 }

  condition:
    any of them
}