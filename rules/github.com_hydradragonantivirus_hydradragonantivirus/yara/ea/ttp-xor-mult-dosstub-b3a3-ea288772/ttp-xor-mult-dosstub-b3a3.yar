rule TTP_XOR_MULT_DOSStub_b3a3 {
  strings:
    $key_b3a3 = { e7 cb [2] 93 d3 [2] d4 d1 [2] 93 c0 [2] dd cc [2] d1 c6 [2] c6 cd [2] dd 83 [2] e0 }

  condition:
    any of them
}