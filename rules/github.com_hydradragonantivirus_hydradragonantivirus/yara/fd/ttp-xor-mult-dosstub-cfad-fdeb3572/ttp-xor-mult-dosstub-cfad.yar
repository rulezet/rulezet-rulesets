rule TTP_XOR_MULT_DOSStub_cfad {
  strings:
    $key_cfad = { 9b c5 [2] ef dd [2] a8 df [2] ef ce [2] a1 c2 [2] ad c8 [2] ba c3 [2] a1 8d [2] 9c }

  condition:
    any of them
}