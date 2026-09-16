rule TTP_XOR_MULT_DOSStub_8fc6 {
  strings:
    $key_8fc6 = { db ae [2] af b6 [2] e8 b4 [2] af a5 [2] e1 a9 [2] ed a3 [2] fa a8 [2] e1 e6 [2] dc }

  condition:
    any of them
}