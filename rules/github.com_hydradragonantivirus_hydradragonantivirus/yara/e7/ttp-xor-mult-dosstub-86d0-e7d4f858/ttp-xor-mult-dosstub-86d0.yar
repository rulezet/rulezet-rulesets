rule TTP_XOR_MULT_DOSStub_86d0 {
  strings:
    $key_86d0 = { d2 b8 [2] a6 a0 [2] e1 a2 [2] a6 b3 [2] e8 bf [2] e4 b5 [2] f3 be [2] e8 f0 [2] d5 }

  condition:
    any of them
}