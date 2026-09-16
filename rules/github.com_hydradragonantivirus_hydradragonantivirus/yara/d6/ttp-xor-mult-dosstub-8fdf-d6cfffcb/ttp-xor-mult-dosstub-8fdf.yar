rule TTP_XOR_MULT_DOSStub_8fdf {
  strings:
    $key_8fdf = { db b7 [2] af af [2] e8 ad [2] af bc [2] e1 b0 [2] ed ba [2] fa b1 [2] e1 ff [2] dc }

  condition:
    any of them
}