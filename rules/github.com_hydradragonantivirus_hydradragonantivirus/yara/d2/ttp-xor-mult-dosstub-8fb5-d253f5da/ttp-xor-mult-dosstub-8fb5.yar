rule TTP_XOR_MULT_DOSStub_8fb5 {
  strings:
    $key_8fb5 = { db dd [2] af c5 [2] e8 c7 [2] af d6 [2] e1 da [2] ed d0 [2] fa db [2] e1 95 [2] dc }

  condition:
    any of them
}