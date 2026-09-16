rule TTP_XOR_MULT_DOSStub_cdb9 {
  strings:
    $key_cdb9 = { 99 d1 [2] ed c9 [2] aa cb [2] ed da [2] a3 d6 [2] af dc [2] b8 d7 [2] a3 99 [2] 9e }

  condition:
    any of them
}