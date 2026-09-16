rule TTP_XOR_MULT_DOSStub_cfa7 {
  strings:
    $key_cfa7 = { 9b cf [2] ef d7 [2] a8 d5 [2] ef c4 [2] a1 c8 [2] ad c2 [2] ba c9 [2] a1 87 [2] 9c }

  condition:
    any of them
}