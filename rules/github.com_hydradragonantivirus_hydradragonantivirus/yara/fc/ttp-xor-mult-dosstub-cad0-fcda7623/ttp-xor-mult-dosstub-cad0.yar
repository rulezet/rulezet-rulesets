rule TTP_XOR_MULT_DOSStub_cad0 {
  strings:
    $key_cad0 = { 9e b8 [2] ea a0 [2] ad a2 [2] ea b3 [2] a4 bf [2] a8 b5 [2] bf be [2] a4 f0 [2] 99 }

  condition:
    any of them
}