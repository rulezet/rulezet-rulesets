rule TTP_XOR_MULT_DOSStub_cdb4 {
  strings:
    $key_cdb4 = { 99 dc [2] ed c4 [2] aa c6 [2] ed d7 [2] a3 db [2] af d1 [2] b8 da [2] a3 94 [2] 9e }

  condition:
    any of them
}