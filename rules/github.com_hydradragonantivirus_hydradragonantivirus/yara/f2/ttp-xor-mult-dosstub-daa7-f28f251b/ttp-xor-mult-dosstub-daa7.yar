rule TTP_XOR_MULT_DOSStub_daa7 {
  strings:
    $key_daa7 = { 8e cf [2] fa d7 [2] bd d5 [2] fa c4 [2] b4 c8 [2] b8 c2 [2] af c9 [2] b4 87 [2] 89 }

  condition:
    any of them
}