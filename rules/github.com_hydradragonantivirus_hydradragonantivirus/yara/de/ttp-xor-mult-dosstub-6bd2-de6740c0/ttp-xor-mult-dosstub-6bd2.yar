rule TTP_XOR_MULT_DOSStub_6bd2 {
  strings:
    $key_6bd2 = { 3f ba [2] 4b a2 [2] 0c a0 [2] 4b b1 [2] 05 bd [2] 09 b7 [2] 1e bc [2] 05 f2 [2] 38 }

  condition:
    any of them
}