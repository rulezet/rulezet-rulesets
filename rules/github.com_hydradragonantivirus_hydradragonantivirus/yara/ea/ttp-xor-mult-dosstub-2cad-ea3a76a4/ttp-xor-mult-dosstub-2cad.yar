rule TTP_XOR_MULT_DOSStub_2cad {
  strings:
    $key_2cad = { 78 c5 [2] 0c dd [2] 4b df [2] 0c ce [2] 42 c2 [2] 4e c8 [2] 59 c3 [2] 42 8d [2] 7f }

  condition:
    any of them
}