rule TTP_XOR_MULT_DOSStub_1ab4 {
  strings:
    $key_1ab4 = { 4e dc [2] 3a c4 [2] 7d c6 [2] 3a d7 [2] 74 db [2] 78 d1 [2] 6f da [2] 74 94 [2] 49 }

  condition:
    any of them
}