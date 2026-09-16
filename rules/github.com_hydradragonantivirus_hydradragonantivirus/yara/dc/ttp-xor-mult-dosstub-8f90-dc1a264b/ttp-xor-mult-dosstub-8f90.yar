rule TTP_XOR_MULT_DOSStub_8f90 {
  strings:
    $key_8f90 = { db f8 [2] af e0 [2] e8 e2 [2] af f3 [2] e1 ff [2] ed f5 [2] fa fe [2] e1 b0 [2] dc }

  condition:
    any of them
}