rule TTP_XOR_MULT_DOSStub_c5d1 {
  strings:
    $key_c5d1 = { 91 b9 [2] e5 a1 [2] a2 a3 [2] e5 b2 [2] ab be [2] a7 b4 [2] b0 bf [2] ab f1 [2] 96 }

  condition:
    any of them
}