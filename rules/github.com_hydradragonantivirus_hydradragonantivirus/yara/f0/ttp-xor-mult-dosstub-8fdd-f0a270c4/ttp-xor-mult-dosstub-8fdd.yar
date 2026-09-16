rule TTP_XOR_MULT_DOSStub_8fdd {
  strings:
    $key_8fdd = { db b5 [2] af ad [2] e8 af [2] af be [2] e1 b2 [2] ed b8 [2] fa b3 [2] e1 fd [2] dc }

  condition:
    any of them
}