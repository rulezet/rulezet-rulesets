rule TTP_XOR_MULT_DOSStub_8fd3 {
  strings:
    $key_8fd3 = { db bb [2] af a3 [2] e8 a1 [2] af b0 [2] e1 bc [2] ed b6 [2] fa bd [2] e1 f3 [2] dc }

  condition:
    any of them
}