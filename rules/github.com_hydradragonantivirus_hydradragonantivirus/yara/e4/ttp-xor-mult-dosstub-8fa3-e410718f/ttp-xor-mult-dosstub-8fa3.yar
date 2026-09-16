rule TTP_XOR_MULT_DOSStub_8fa3 {
  strings:
    $key_8fa3 = { db cb [2] af d3 [2] e8 d1 [2] af c0 [2] e1 cc [2] ed c6 [2] fa cd [2] e1 83 [2] dc }

  condition:
    any of them
}