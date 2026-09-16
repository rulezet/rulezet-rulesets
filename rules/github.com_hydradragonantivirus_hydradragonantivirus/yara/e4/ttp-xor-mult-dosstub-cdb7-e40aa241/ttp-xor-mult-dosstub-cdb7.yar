rule TTP_XOR_MULT_DOSStub_cdb7 {
  strings:
    $key_cdb7 = { 99 df [2] ed c7 [2] aa c5 [2] ed d4 [2] a3 d8 [2] af d2 [2] b8 d9 [2] a3 97 [2] 9e }

  condition:
    any of them
}