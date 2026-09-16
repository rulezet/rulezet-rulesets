rule TTP_XOR_MULT_DOSStub_8780 {
  strings:
    $key_8780 = { d3 e8 [2] a7 f0 [2] e0 f2 [2] a7 e3 [2] e9 ef [2] e5 e5 [2] f2 ee [2] e9 a0 [2] d4 }

  condition:
    any of them
}