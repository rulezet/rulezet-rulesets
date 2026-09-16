rule TTP_XOR_MULT_DOSStub_bad2 {
  strings:
    $key_bad2 = { ee ba [2] 9a a2 [2] dd a0 [2] 9a b1 [2] d4 bd [2] d8 b7 [2] cf bc [2] d4 f2 [2] e9 }

  condition:
    any of them
}