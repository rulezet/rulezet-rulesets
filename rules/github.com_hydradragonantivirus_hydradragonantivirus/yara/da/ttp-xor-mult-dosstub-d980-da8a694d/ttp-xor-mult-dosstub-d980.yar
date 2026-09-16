rule TTP_XOR_MULT_DOSStub_d980 {
  strings:
    $key_d980 = { 8d e8 [2] f9 f0 [2] be f2 [2] f9 e3 [2] b7 ef [2] bb e5 [2] ac ee [2] b7 a0 [2] 8a }

  condition:
    any of them
}