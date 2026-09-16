rule TTP_XOR_MULT_DOSStub_bcad {
  strings:
    $key_bcad = { e8 c5 [2] 9c dd [2] db df [2] 9c ce [2] d2 c2 [2] de c8 [2] c9 c3 [2] d2 8d [2] ef }

  condition:
    any of them
}