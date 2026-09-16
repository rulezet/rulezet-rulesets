rule TTP_XOR_MULT_DOSStub_6ad2 {
  strings:
    $key_6ad2 = { 3e ba [2] 4a a2 [2] 0d a0 [2] 4a b1 [2] 04 bd [2] 08 b7 [2] 1f bc [2] 04 f2 [2] 39 }

  condition:
    any of them
}