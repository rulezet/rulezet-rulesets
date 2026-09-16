rule TTP_XOR_MULT_DOSStub_8fda {
  strings:
    $key_8fda = { db b2 [2] af aa [2] e8 a8 [2] af b9 [2] e1 b5 [2] ed bf [2] fa b4 [2] e1 fa [2] dc }

  condition:
    any of them
}