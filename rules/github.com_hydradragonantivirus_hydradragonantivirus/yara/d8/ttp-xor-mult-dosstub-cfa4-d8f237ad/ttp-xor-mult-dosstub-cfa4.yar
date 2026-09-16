rule TTP_XOR_MULT_DOSStub_cfa4 {
  strings:
    $key_cfa4 = { 9b cc [2] ef d4 [2] a8 d6 [2] ef c7 [2] a1 cb [2] ad c1 [2] ba ca [2] a1 84 [2] 9c }

  condition:
    any of them
}