rule TTP_XOR_MULT_DOSStub_8fd1 {
  strings:
    $key_8fd1 = { db b9 [2] af a1 [2] e8 a3 [2] af b2 [2] e1 be [2] ed b4 [2] fa bf [2] e1 f1 [2] dc }

  condition:
    any of them
}