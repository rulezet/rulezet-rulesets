rule TTP_XOR_MULT_DOSStub_8f86 {
  strings:
    $key_8f86 = { db ee [2] af f6 [2] e8 f4 [2] af e5 [2] e1 e9 [2] ed e3 [2] fa e8 [2] e1 a6 [2] dc }

  condition:
    any of them
}