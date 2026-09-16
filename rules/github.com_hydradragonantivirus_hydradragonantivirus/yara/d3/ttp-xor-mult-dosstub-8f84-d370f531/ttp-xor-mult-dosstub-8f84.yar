rule TTP_XOR_MULT_DOSStub_8f84 {
  strings:
    $key_8f84 = { db ec [2] af f4 [2] e8 f6 [2] af e7 [2] e1 eb [2] ed e1 [2] fa ea [2] e1 a4 [2] dc }

  condition:
    any of them
}