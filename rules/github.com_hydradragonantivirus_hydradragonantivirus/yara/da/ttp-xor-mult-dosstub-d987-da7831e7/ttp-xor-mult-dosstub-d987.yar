rule TTP_XOR_MULT_DOSStub_d987 {
  strings:
    $key_d987 = { 8d ef [2] f9 f7 [2] be f5 [2] f9 e4 [2] b7 e8 [2] bb e2 [2] ac e9 [2] b7 a7 [2] 8a }

  condition:
    any of them
}