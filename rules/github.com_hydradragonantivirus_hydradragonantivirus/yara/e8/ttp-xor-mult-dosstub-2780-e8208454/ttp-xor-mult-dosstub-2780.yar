rule TTP_XOR_MULT_DOSStub_2780 {
  strings:
    $key_2780 = { 73 e8 [2] 07 f0 [2] 40 f2 [2] 07 e3 [2] 49 ef [2] 45 e5 [2] 52 ee [2] 49 a0 [2] 74 }

  condition:
    any of them
}