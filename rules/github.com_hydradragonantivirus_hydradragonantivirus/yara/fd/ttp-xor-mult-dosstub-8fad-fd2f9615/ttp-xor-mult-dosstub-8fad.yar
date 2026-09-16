rule TTP_XOR_MULT_DOSStub_8fad {
  strings:
    $key_8fad = { db c5 [2] af dd [2] e8 df [2] af ce [2] e1 c2 [2] ed c8 [2] fa c3 [2] e1 8d [2] dc }

  condition:
    any of them
}