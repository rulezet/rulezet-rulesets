rule TTP_XOR_MULT_DOSStub_cfa5 {
  strings:
    $key_cfa5 = { 9b cd [2] ef d5 [2] a8 d7 [2] ef c6 [2] a1 ca [2] ad c0 [2] ba cb [2] a1 85 [2] 9c }

  condition:
    any of them
}