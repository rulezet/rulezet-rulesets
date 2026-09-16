rule TTP_XOR_MULT_DOSStub_b780 {
  strings:
    $key_b780 = { e3 e8 [2] 97 f0 [2] d0 f2 [2] 97 e3 [2] d9 ef [2] d5 e5 [2] c2 ee [2] d9 a0 [2] e4 }

  condition:
    any of them
}