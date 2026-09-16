rule TTP_XOR_MULT_DOSStub_4ab4 {
  strings:
    $key_4ab4 = { 1e dc [2] 6a c4 [2] 2d c6 [2] 6a d7 [2] 24 db [2] 28 d1 [2] 3f da [2] 24 94 [2] 19 }

  condition:
    any of them
}